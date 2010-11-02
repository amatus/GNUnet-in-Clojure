(ns org.gnu.clojure.gnunet.filesharing
  (:use (org.gnu.clojure.gnunet bloomfilter crypto message parser peer)
    clojure.contrib.monads))

(def message-type-fs-get 137)
(def message-type-fs-put 138)
(def message-type-fs-migration-stop 139)

(def bit-return-to 1)
(def bit-sks-namespace 2)
(def bit-transmit-to 3)

(def parse-get-message
  (domonad parser-m
    [block-type parse-int32
     priority parse-uint32
     ttl parse-int32
     filter-mutator parse-int32
     hash-bitmap parse-int32
     query (items hash-size)
     return-to (conditional (bit-test hash-bitmap bit-return-to)
                 (items id-size))
     sks-namespace (conditional (bit-test hash-bitmap bit-sks-namespace)
                     (items hash-size))
     transmit-to (conditional (bit-test hash-bitmap bit-transmit-to)
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
  [priority remote-peer]
  )

(defn admit-get!
  [peer remote-peer message]
  (when-let [get-message (first (parse-get-message (:bytes message)))]
    (.write *out* (.toString get-message))
    (.write *out* "\n")
    )
  (when-let [return-to (if (:return-to message)
                         ((deref (:remote-peers-agent peer))
                           (:return-to message))
                         remote-peer)]
    (when-let [priority (bound-priority (:priority message) remote-peer)]
      )))
        

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
