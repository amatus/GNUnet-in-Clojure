(ns org.gnu.clojure.gnunet.filesharing
  (:use (org.gnu.clojure.gnunet bloomfilter crypto exception message parser
          peer)
    clojure.contrib.monads))

(def message-type-fs-get 137)
(def message-type-fs-put 138)
(def message-type-fs-migration-stop 139)

(def bit-return-to 1)
(def bit-sks-namespace 2)
(def bit-transmit-to 3)

(def ttl-decrement 5000)
(def ttl-max 1073741824)

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
  [priority]
  (fn [state]
    (let [priority (min priority (:turst state 0))
          trust (- (:trust state) priority)
          state (assoc state :trust trust)]
      (if (< 0 priority)
        (let [n 128
              average (:average-priority state 0.0)
              p (min priority (+ average n))
              average (/ (+ p (* average (dec n))) n)]
          [priority (assoc state :average-priority average)])
        [priority state]))))

(defn admit-get!
  [peer remote-peer message]
  (send-do-exception-m! (:state-agent remote-peer)
    [:when-let [get-message (first (parse-get-message (:bytes message)))]
     :let [_ (.write *out* (str get-message "\n"))]
     :when-let [return-to (if (:return-to get-message)
                            ((deref (:remote-peers-agent peer))
                              (:return-to get-message))
                            remote-peer)]
     :when (:is-connected (deref (:state-agent return-to))) ;; TODO: try connect
     ;; TODO: check load and drop message if load is too high
     priority (bound-priority (:priority get-message))
     :let [ttl (min ttl-max (:ttl get-message)
                 (* priority ttl-decrement 0.001))]
     :let [ttl (- ttl (* 2 ttl-decrement)
                 (.nextInt (:random peer) ttl-decrement))]
     :when (< 0 ttl)]
      nil))

(defn admit-put!
  [peer remote-peer message])

(defn admit-migration-stop!
  [peer remote-peer message])

(defn activate-filesharing!
  [peer]
  (send (:dispatch-agent peer)
    (fn [dispatchers]
      (let [get-dispatchers (dispatchers message-type-fs-get #{})
            put-dispatchers (dispatchers message-type-fs-put #{})
            migration-stop-dispatchers
            (dispatchers message-type-fs-migration-stop #{})]
        (conj dispatchers
          {message-type-fs-get (conj get-dispatchers admit-get!)
           message-type-fs-put (conj put-dispatchers admit-put!)
           message-type-fs-migration-stop (conj migration-stop-dispatchers
                                            admit-migration-stop!)})))))
