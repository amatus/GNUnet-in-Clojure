(ns org.gnu.clojure.gnunet.filesharing
  (:use (org.gnu.clojure.gnunet bloomfilter core crypto exception message
          metrics parser peer)
    clojure.contrib.monads)
  (:import (java.util Date PriorityQueue)
    java.util.concurrent.TimeUnit))

(def message-type-fs-get 137)
(def message-type-fs-put 138)
(def message-type-fs-migration-stop 139)

(def bit-return-to 0)
(def bit-sks-namespace 1)
(def bit-transmit-to 2)

(def ttl-decrement 5000)
(def ttl-max 1073741824)
(def max-pending-requests 32768)

(defn encode-get-message
  [get-message]
  (let [hash-bitmap 0
        hash-bitmap (if (nil? (:return-to get-message))
                      hash-bitmap
                      (bit-set hash-bitmap bit-return-to))
        hash-bitmap (if (nil? (:sks-namespace get-message))
                      hash-bitmap
                      (bit-set hash-bitmap bit-sks-namespace))
        hash-bitmap (if (nil? (:transmit-to get-message))
                      hash-bitmap
                      (bit-set hash-bitmap bit-transmit-to))]
    (concat
      (encode-int32 (:block-type get-message))
      (encode-int32 (:priority get-message))
      (encode-int32 (:ttl get-message))
      (encode-int32 (:filter-mutator get-message))
      (encode-int32 hash-bitmap)
      (:return-to get-message)
      (:sks-namespace get-message)
      (:transmit-to get-message)
      (when (:bloomfilter get-message)
        (encode-bloomfilter (:bloomfilter get-message))))))

(def parse-get-message
  (domonad parser-m
    [block-type parse-int32
     priority parse-uint32
     ttl parse-int32
     filter-mutator parse-int32
     hash-bitmap parse-int32
     query (items hash-size)
     return-to (m-when (bit-test hash-bitmap bit-return-to)
                 (items id-size))
     sks-namespace (m-when (bit-test hash-bitmap bit-sks-namespace)
                     (items hash-size))
     transmit-to (m-when (bit-test hash-bitmap bit-transmit-to)
                   (items id-size))
     bloomfilter (optional (parse-bloomfilter bloomfilter-k))]
    {:block-type block-type
     :priority priority
     :ttl ttl
     :filter-mutator filter-mutator
     :query query
     :return-to return-to
     :sks-namespace sks-namespace
     :transmit-to transmit-to
     :bloomfilter bloomfilter}))

(defn bound-priority
  "Monadic function of the exception-m monad. Updates :trust and
   :average-priority and returns a bounded priority."
  [peer priority]
  (domonad exception-m
    [;; TODO: come up with a better load-limit
     :let [load-limit (+ (network-load peer) (cpu-load peer) (disk-load peer))]
     :let [priority (if (== 0 load-limit)
                      (do
                        (metric-add! peer "Filesharing requests done for free" 1)
                        0)
                      priority)]
     trust (fetch-val :trust 0)
     :let [priority (min priority trust)]
     _ (update-val :average-priority 0.0
         #(if (< 0 priority)
            (let [n 128
                  p (min priority (+ % n))]
              (/ (+ p (* % (dec n))) n))
            %))
     :when (if (<= load-limit priority)
             true
             (do (metric-add! peer
                   "Filesharing requests dropped, priority insufficient" 1)
               false))
     _ (set-val :trust (- trust priority))]
    priority))

(defn get-processing-delay!
  [peer]
  (long (+ 1000 (.nextInt (:random peer) ttl-decrement))))

(defn target-peer-select
  [return-to-id best candidate]
  (if (= return-to-id (key candidate))
    best
    ;; TODO: come on, seriously?
    candidate))

(defn forward-request!
  [peer query-id return-to-id]
  (send-do-exception-m! (:state-agent peer)
    [query (with-state-field :queries
             (with-state-field query-id
               (fetch-val return-to-id)))
     :when-not (nil? query)
     :let [send-to (reduce (partial target-peer-select return-to-id) nil
                     (deref (:remote-peers-agent peer)))]
     :when (if (nil? send-to)
             (do (.schedule (:scheduled-executor peer)
                   (partial forward-request! peer query-id return-to-id)
                   (get-processing-delay! peer)
                   TimeUnit/MILLISECONDS)
               (metric-add! peer
                 "Filesharing requests delayed, no suitable destination" 1)
               false)
             true)]
    (send-do-exception-m! (:state-agent send-to)
      [is-connected (fetch-val :is-connected)
       status (fetch-val :status)
       :when (if (and is-connected (== status peer-status-key-confirmed))
               true
               (do (.schedule (:scheduled-executor peer)
                     (partial forward-request! peer query-id return-to-id)
                     (get-processing-delay! peer)
                     TimeUnit/MILLISECONDS)
                 false))]
      (let [get-message (encode-get-message query)]
        (core-send! peer send-to
          {:message-type message-type-fs-get :bytes get-message})))))

(def ttl-comparator
  (reify java.util.Comparator
    (compare [this o1 o2]
      (clojure.core/compare (:ttl (meta o1)) (:ttl (meta o2))))
    (equals [this obj]
      (== (:ttl (meta this)) (:ttl (meta obj))))))

(defn admit-get!
  [peer remote-peer message]
  (send-do-exception-m! (:state-agent remote-peer)
    [:when-let [get-message (first (parse-get-message (:bytes message)))]
     :let [_ (.write *out* (str get-message "\n"))]
     :when-let [return-to (if (:return-to get-message)
                            ((deref (:remote-peers-agent peer))
                              (:return-to get-message))
                            remote-peer)]
     :when (if (:is-connected (deref (:state-agent return-to)))
             true
             ;; TODO: try connect
             (do (metric-add! peer
                   "Filesharing requests dropped, missing reverse route" 1)
               false))
     priority (bound-priority peer (:priority get-message))
     :let [ttl (min ttl-max (:ttl get-message)
                 (* priority ttl-decrement 0.001))]
     :let [ttl (- ttl (* 2 ttl-decrement)
                 (.nextInt (:random peer) ttl-decrement))]
     :let [start-time (Date.)]]
    (send-do-exception-m! (:state-agent peer)
      [queries (fetch-val :queries {})
       :let [query (queries (:query get-message) {})]
       :let [duplicate (query (:id return-to))]
       :when (if (nil? duplicate)
               true
               (do (metric-add! peer "Filehsaring requests dropped, duplicate" 1)
                 false))
       :let [queries (assoc queries (:query get-message)
                       (assoc query (:id return-to)
                         (conj get-message
                           {:priority priority
                            :ttl ttl
                            :start-time start-time
                            :anonymity 1
                            :return-to nil})))]
       ttl-queue (fetch-val :ttl-queue (PriorityQueue. 1 ttl-comparator))
       :let [_ (.add ttl-queue (with-meta [(:query get-message) (:id return-to)]
                                 {:ttl (+ ttl (.getTime start-time))}))]
       :let [_ (metric-set! peer
                 "Filesharing pending requests" (.size ttl-queue))]
       :let [expired (when (< max-pending-requests (.size ttl-queue))
                       (.poll ttl-queue))]
       :let [queries (if (nil? expired)
                       queries
                       (let [query (dissoc (queries (first expired))
                                     (second expired))]
                         (if (empty? query)
                           (dissoc queries (first expired))
                           (assoc queries (first expired) query))))]
       _ (set-val :queries queries)]
      (forward-request! peer (:query get-message) (:id return-to)))))

(defn admit-put!
  [peer remote-peer message])

(defn admit-migration-stop!
  [peer remote-peer message])

(defn activate-filesharing!
  [peer]
  (core-register-dispatchers!
    peer
    [message-type-fs-get admit-get!
     message-type-fs-put admit-put!
     message-type-fs-migration-stop admit-migration-stop!]))
