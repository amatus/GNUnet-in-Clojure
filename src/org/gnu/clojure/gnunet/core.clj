(ns org.gnu.clojure.gnunet.core
  (:use (org.gnu.clojure.gnunet parser message peer crypto)
    clojure.contrib.monads)
  (:import java.util.Date))

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
  (send (:core-state-agent remote-peer)
    (fn [state]
      (if-let [public-key (deref (:public-key-atom remote-peer))]
        (if-let [set-key (first (parse-set-key (:bytes message)))]
          (let [status (state :status :status-down)
                decrypt-key-created (state :decrypt-key-created (Date. 0))]
            (cond
              (not (= (:peer-id set-key) (seq (:id peer)))) state
              (not (rsa-verify public-key
                     (:signed-material set-key) (:signature set-key))) state
              (and
                (or (= status :status-key-received)
                  (= status :status-key-confirmed))
                (< (:creation-time set-key) decrypt-key-created)) state
              :else (let [decrypt-key (rsa-decrypt (:private-key peer)
                                        (:encrypted-key set-key))]
                      state)))
          state)
        state))))

(defn handle-receive!
  [peer remote-peer message]
  (condp = (:message-type message)
    message-type-core-set-key (handle-set-key! peer remote-peer message)
    message-type-core-encrypted-message nil
    message-type-core-ping nil
    message-type-core-pong nil
    nil))
