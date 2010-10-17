(ns org.gnu.clojure.gnunet.core
  (:use (org.gnu.clojure.gnunet parser message peer crypto)
    clojure.contrib.monads)
  (:import java.util.Date))

(def message-type-core-set-key 80)
(def message-type-core-encrypted-message 81)
(def message-type-core-ping 82)
(def message-type-core-pong 83)

(def signature-purpose-set-key 3)

(def peer-status-down 0)
(def peer-status-key-sent 1)
(def peer-status-key-received 2)
(def peer-status-key-confirmed 3)

(defn encode-set-key-signed-material
  [set-key]
  (encode-signed signature-purpose-set-key
    (concat
      (encode-date (:creation-time set-key))
      (:encrypted-key set-key)
      (:peer-id set-key))))

(defn encode-set-key
  [set-key signed-material]
  (concat
    (encode-int32 (:sender-status set-key))
    signed-material
    (:signature set-key)))

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

(defn encode-core-ping
  [ping]
  (concat
    (encode-int32 (:iv-seed ping))
    (:peer-id ping)
    (encode-int32 (:challenge ping))))

(def parse-core-ping
  (domonad parser-m [iv-seed parse-uint32
                     peer-id (items id-size)
                     challenge parse-int32]
    {:iv-seed iv-seed
     :peer-id peer-id
     :challenge challenge}))

(defn derive-iv
  [aes-key seed peer-id]
  (derive-aes-iv aes-key
    (encode-int32 seed)
    (concat
      peer-id
      (encode-utf8 "initialization vector"))))

(defn encrypt-message
  [aes-key iv message]
  (let [iv-seed (take 4 message)
        plaintext (drop 4 message)]
    (concat
      iv-seed
      (aes-encrypt aes-key iv plaintext))))

(defn emit-messages!
  [peer remote-peer messages]
  (send (:state-agent remote-peer)
    (fn [state]
      (if (:is-connected state)
        (let [transport (:connected-transport state)
              encoded-address (:connected-address state)]
          ((:emit-messages! transport) transport remote-peer
            encoded-address nil messages)))
      state)))

(defn send-key!
  [peer remote-peer]
  (send (:state-agent remote-peer)
    (fn [state]
      (if-let [public-key (deref (:public-key-atom remote-peer))]
        (if (:is-connected state)
          (let [state (if (= peer-status-down (:status state))
                        (assoc state :status peer-status-key-sent)
                        state)
                set-key {:sender-status (:status state)
                         :creation-time (:encrypt-key-created state)
                         :peer-id (:id remote-peer)
                         :encrypted-key (rsa-encrypt! (:public-key peer)
                                          (:encrypt-key state)
                                          (:random peer))}
                signed-material (encode-set-key-signed-material set-key)
                signature (rsa-sign (:private-key peer) signed-material)
                set-key (assoc set-key :signature signature)
                encoded-set-key (encode-set-key set-key signed-material)
                iv-seed (.nextInt (:random peer))
                ping {:iv-seed iv-seed
                      :challenge (:ping-challenge state)
                      :peer-id (:id remote-peer)}
                encoded-ping (encode-core-ping ping)
                iv (derive-iv (:encrypt-key state) iv-seed (:id remote-peer))
                encrypted-ping (encrypt-message (:encrypt-key state) iv
                                 encoded-ping)]
            (emit-messages! peer remote-peer
              [{:message-type message-type-core-set-key
                :bytes encoded-set-key}
               {:message-type message-type-core-ping
                :bytes encrypted-ping}])
            state)
          state)
        state))))

(defn verify-set-key
  [peer remote-peer state message]
  (when-let [public-key (deref (:public-key-atom remote-peer))]
    (when-let [set-key (first (parse-set-key (:bytes message)))]
      (let [status (:status state)
            decrypt-key-created (:decrypt-key-created state)]
        (cond
          (not (= (:peer-id set-key) (seq (:id peer)))) nil
          (not (rsa-verify public-key
                 (:signed-material set-key) (:signature set-key))) nil
          (and
            (or (= status peer-status-key-received)
              (= status peer-status-key-confirmed))
            (< (:creation-time set-key) decrypt-key-created)) nil
          :else set-key)))))

(defn handle-set-key!
  [peer remote-peer message]
  (send (:state-agent remote-peer)
    (fn [state]
      (if-let [set-key (verify-set-key peer remote-peer state message)]
        (if-let [decrypt-key (rsa-decrypt (:private-key peer)
                               (:encrypted-key set-key))]
          (let [state (assoc state :decrypt-key decrypt-key)
                decrypt-key-created (state :decrypt-key-created (Date. 0))
                creation-time (:creation-time set-key)
                state (if (= decrypt-key-created creation-time)
                        state
                        (conj state {:last-sequence-number-received 0
                                     :last-packets-bitmap 0
                                     :decrypt-key-created creation-time}))
                status (state :status peer-status-down)
                sender-status (:sender-status set-key)]
            (condp contains? status
              #{peer-status-down}
              (do (send-key! peer remote-peer)
                (assoc state :status peer-status-key-received))
              #{peer-status-key-sent
                peer-status-key-received}
              (do (if (and (not (= sender-status peer-status-key-received))
                        (not (= sender-status peer-status-key-confirmed)))
                    (send-key! peer remote-peer))
                (assoc state :status peer-status-key-received))
              #{peer-status-key-confirmed}
              (do (if (and (not (= sender-status peer-status-key-received))
                        (not (= sender-status peer-status-key-confirmed)))
                    (send-key! peer remote-peer))
                state)
              state))
          state)
        state))))

(defn initialize-remote-peer-state
  [peer state]
  (conj state
    {:status peer-status-down
     :decrypt-key-created (Date. 0)
     :encrypt-key (generate-aes-key! (:random peer))
     :encrypt-key-created (Date.)
     :ping-challenge (.nextInt (:random peer))}))

(defn handle-receive!
  [peer remote-peer message]
  (send (:state-agent remote-peer)
    (fn [state]
      (let [state (if (contains? state :status)
                    state
                    (initialize-remote-peer-state peer state))]
        (condp = (:message-type message)
          message-type-core-set-key (handle-set-key! peer remote-peer message)
          message-type-core-encrypted-message nil
          message-type-core-ping nil
          message-type-core-pong nil
          nil)
        state))))
