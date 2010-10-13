(ns org.gnu.clojure.gnunet.core
  (:use (org.gnu.clojure.gnunet parser message peer crypto)
    clojure.contrib.monads))

(def message-type-core-set-key 80)
(def message-type-core-encrypted-message 81)
(def message-type-core-ping 82)
(def message-type-core-pong 83)

(def signature-purpose-set-key 3)

(def parse-set-key
  (domonad parser-m
    [sender-status parse-int32
     signed (parse-signed
              (domonad parser-m
                [creation-time parse-date
                 encrypted-key (items signature-size)
                 peer-id (items id-size)]
                {:creation-time creation-time
                 :encrypted-key encrypted-key
                 :peer-id peer-id}))
    :let [signature-purpose (:purpose signed)]
    :when (= signature-purpose signature-purpose-set-key)
    signature (items signature-size)]
    (conj
      {:sender-status sender-status
       :signed-material (:signed-material signed)
       :signature signature}
      (:parsed signed))))


(defn handle-set-key!
  [peer remote-peer message]
  (when-let [public-key (deref (:public-key-atom remote-peer))]
    (when-let [set-key (first (parse-set-key (:bytes message)))]
      (cond
        (not (= (:peer-id set-key) (seq (:id peer)))) (.write *out* "SET_KEY not for me\n")
        (not (rsa-verify public-key
               (:signed-material set-key)
               (:signature set-key))) (.write *out* "SET_KEY invalid signature\n")
        :else (do (.write *out* "Set key message ")
                (.write *out* (.toString set-key))
                (.write *out* "\n"))
        ))))

(defn handle-receive!
  [peer remote-peer message]
  (condp = (:message-type message)
    message-type-core-set-key (handle-set-key! peer remote-peer message)
    message-type-core-encrypted-message nil
    message-type-core-ping nil
    message-type-core-pong nil
    nil))
