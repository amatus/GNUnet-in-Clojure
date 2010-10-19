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
  (domonad parser-m [iv-seed parse-int32
                     peer-id (items id-size)
                     challenge parse-int32]
    {:iv-seed iv-seed
     :peer-id peer-id
     :challenge challenge}))

(defn encode-core-pong
  [pong]
  (concat
    (encode-int32 (:iv-seed pong))
    (encode-int32 (:challenge pong))
    (encode-int32 (:inbound-bw-limit pong))
    (:peer-id pong)))

(def parse-core-pong
  (domonad parser-m [iv-seed parse-int32
                     challenge parse-int32
                     inbound-bw-limit parse-uint32
                     peer-id (items id-size)]
    {:iv-seed iv-seed
     :challenge challenge
     :inbound-bw-limit inbound-bw-limit
     :peer-id peer-id}))

(defn derive-iv
  [aes-key seed peer-id]
  (derive-aes-iv aes-key
    (encode-int32 seed)
    (concat
      peer-id
      (encode-utf8 "initialization vector"))))

(defn derive-pong-iv
  [aes-key seed challenge peer-id]
  (derive-aes-iv aes-key
    (encode-int32 seed)
    (concat
      peer-id
      (encode-int32 challenge)
      (encode-utf8 "pong initialization vector"))))

(defn encrypt-message
  [aes-key iv message]
  (let [iv-seed (take 4 message)
        plaintext (drop 4 message)]
    (concat
      iv-seed
      (aes-encrypt aes-key iv plaintext))))

(defn decrypt-message
  [aes-key iv message]
  (let [iv-seed (take 4 message)
        ciphertext (drop 4 message)]
    (concat
      iv-seed
      (aes-decrypt aes-key iv ciphertext))))

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
                         :encrypted-key (rsa-encrypt!
                                          public-key
                                          (encode-aes-key (:encrypt-key state))
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
                aes-key (:encrypt-key state)
                iv (derive-iv aes-key iv-seed (:id remote-peer))
                encrypted-ping (encrypt-message aes-key iv encoded-ping)]
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
            (< 0 (.compareTo decrypt-key-created (:creation-time set-key)))) nil
          :else (when-let [decrypted-key (rsa-decrypt (:private-key peer)
                                           (:encrypted-key set-key))]
                  ;; XXX: For some reason we end up with an extra 0 byte at the
                  ;; beginning of the decrypted-key when the MSB is 1.
                  (let [decrypted-key (drop (- (count decrypted-key)
                                              aes-key-size 4)
                                        decrypted-key)]
                    (when-let [decrypt-key (first
                                             (parse-aes-key decrypted-key))]
                      (assoc set-key :decrypt-key decrypt-key)))))))))

(defn handle-set-key!
  [peer remote-peer message]
  (send (:state-agent remote-peer)
    (fn [state]
      (if-let [set-key (verify-set-key peer remote-peer state message)]
        (let [decrypt-key (:decrypt-key set-key)
              state (assoc state :decrypt-key decrypt-key)
              decrypt-key-created (:decrypt-key-created state)
              creation-time (:creation-time set-key)
              state (if (= decrypt-key-created creation-time)
                      state
                      (conj state {:last-sequence-number-received 0
                                   :last-packets-bitmap 0
                                   :decrypt-key-created creation-time}))
              status (:status state)
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
        state))))

(defn handle-core-ping!
  [peer remote-peer message]
  (send (:state-agent remote-peer)
    (fn [state]
      (when-let [decrypt-key (:decrypt-key state)]
        (when-let [ping (first (parse-core-ping (:bytes message)))]
          (let [iv (derive-iv decrypt-key (:iv-seed ping) (:id peer))
                decrypted-message (decrypt-message decrypt-key iv
                                    (:bytes message))]
            (when-let [ping (first (parse-core-ping decrypted-message))]
              (when (= (:peer-id ping) (:id peer))
                (let [iv-seed (.nextInt (:random peer))
                      pong {:iv-seed iv-seed
                            :challenge (:challenge ping)
                            :inbound-bw-limit (:bw-in state)
                            :peer-id (:id peer)}
                      encoded-pong (encode-core-pong pong)
                      aes-key (:encrypt-key state)
                      iv (derive-pong-iv aes-key iv-seed (:challenge pong)
                           (:id remote-peer))
                      encrypted-pong (encrypt-message aes-key iv encoded-pong)]
                  (emit-messages! peer remote-peer
                    [{:message-type message-type-core-pong
                      :bytes encrypted-pong}])))))))
      state)))

(defn handle-core-pong!
  [peer remote-peer message]
  (send (:state-agent remote-peer)
    (fn [state]
      (if-let [decrypt-key (:decrypt-key state)]
        (if-let [pong (first (parse-core-pong (:bytes message)))]
          (let [iv (derive-pong-iv decrypt-key (:iv-seed pong)
                     (:ping-challenge state) (:id peer))
                decrypted-message (decrypt-message decrypt-key iv
                                    (:bytes message))]
            (if-let [pong (first (parse-core-pong decrypted-message))]
              (if (and (= (:peer-id pong) (:id remote-peer))
                    (= (:challenge pong) (:ping-challenge state)))
                (condp = (:status state)
                  peer-status-key-received (assoc state :status
                                             peer-status-key-confirmed)
                  state)
                state)
              state))
          state)
        state))))

(defn initialize-remote-peer-state
  [peer state]
  (conj state
    {:status peer-status-down
     :decrypt-key-created (Date. (long 0))
     :encrypt-key (generate-aes-key! (:random peer))
     :encrypt-key-created (Date.)
     :ping-challenge (.nextInt (:random peer))
     ;; TODO: Make this a real number
     :bw-in 20000}))

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
          message-type-core-ping (handle-core-ping! peer remote-peer message)
          message-type-core-pong (handle-core-pong! peer remote-peer message)
          nil)
        state))))
