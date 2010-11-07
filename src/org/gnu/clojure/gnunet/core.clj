(ns org.gnu.clojure.gnunet.core
  (:use (org.gnu.clojure.gnunet crypto exception message parser peer)
    clojure.contrib.monads)
  (:import (java.util Date Calendar)))

(def message-type-core-set-key 80)
(def message-type-core-encrypted-message 81)
(def message-type-core-ping 82)
(def message-type-core-pong 83)

(def signature-purpose-set-key 3)

(def peer-status-down 0)
(def peer-status-key-sent 1)
(def peer-status-key-received 2)
(def peer-status-key-confirmed 3)

(defn message-expiration
  []
  (.getTime (doto (Calendar/getInstance) (.add Calendar/DAY_OF_YEAR -1))))

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

(defn derive-auth-key
  [aes-key seed aes-key-created]
  (derive-hmac-key aes-key
    (encode-int32 seed)
    (concat
      (.getEncoded aes-key)
      (encode-date aes-key-created)
      (encode-utf8 "authentication key"))))

(defn encode-core-ping
  [ping aes-key remote-peer-id]
  (let [iv (derive-iv aes-key (:iv-seed ping) remote-peer-id)]
    (concat
      (encode-int32 (:iv-seed ping))
      (aes-encrypt aes-key iv
        (concat
          (:peer-id ping)
          (encode-int32 (:challenge ping)))))))

(defn parse-core-ping
  [aes-key peer-id]
  (domonad parser-m
    [iv-seed parse-int32
     ciphertext (none-or-more item)
     :let [iv (derive-iv aes-key iv-seed peer-id)]
     :let [plaintext (aes-decrypt aes-key iv ciphertext)]
     :let [ping (first ((domonad parser-m
                          [peer-id (items id-size)
                           challenge parse-int32]
                          {:peer-id peer-id
                           :challenge challenge})
                         plaintext))]
     :when ping]
    ping))

(defn encode-core-pong
  [pong aes-key remote-peer-id]
  (let [iv (derive-pong-iv aes-key (:iv-seed pong) (:challenge pong)
             remote-peer-id)]
    (concat
      (encode-int32 (:iv-seed pong))
      (aes-encrypt aes-key iv
        (concat
          (encode-int32 (:challenge pong))
          (encode-int32 (:inbound-bw-limit pong))
          (:peer-id pong))))))

(defn parse-core-pong
  [aes-key ping-challenge peer-id]
  (domonad parser-m
    [iv-seed parse-int32
     ciphertext (none-or-more item)
     :let [iv (derive-pong-iv aes-key iv-seed ping-challenge peer-id)]
     :let [plaintext (aes-decrypt aes-key iv ciphertext)]
     :let [pong (first ((domonad parser-m
                          [challenge parse-int32
                           :when (= challenge ping-challenge)
                           inbound-bw-limit parse-uint32
                           peer-id (items id-size)]
                          {:inbound-bw-limit inbound-bw-limit
                           :peer-id peer-id})
                         plaintext))]
     :when pong]
    pong))

(defn parse-core-encrypted-message
  [aes-key aes-key-created peer-id]
  (domonad parser-m
    [iv-seed parse-int32
     hmac (items hash-size)
     ciphertext (none-or-more item)
     :let [auth-key (derive-auth-key aes-key iv-seed aes-key-created)]
     :when (= hmac (seq (hmac-sha-512 auth-key ciphertext)))
     :let [iv (derive-iv aes-key iv-seed peer-id)]
     :let [plaintext (aes-decrypt aes-key iv ciphertext)]
     :let [message (first ((domonad parser-m
                             [sequence-number parse-uint32
                              inbound-bw-limit parse-uint32
                              timestamp parse-date
                              messages (none-or-more parse-message)]
                             {:sequence-number sequence-number
                              :inbound-bw-limit inbound-bw-limit
                              :timestamp timestamp
                              :messages messages})
                            plaintext))]
     :when message]
    message))

(defn emit-messages!
  [peer remote-peer messages]
  (let [state (deref (:state-agent remote-peer))
        transport (:connected-transport state)
        encoded-address (:connected-address state)]
    (when (:is-connected state)
      ((:emit-messages! transport) transport remote-peer encoded-address nil
        messages))))

(defn send-key!
  [peer remote-peer]
  (send-do-exception-m! (:state-agent remote-peer)
    [:when-let [public-key (deref (:public-key-atom remote-peer))]
     is-connected (fetch-val :is-connected)
     :when is-connected
     _ (update-val :status #(if (== % peer-status-down) peer-status-key-sent %))
     sender-status (fetch-val :status)
     creation-time (fetch-val :encrypt-key-created)
     encrypt-key (fetch-val :encrypt-key)
     challenge (fetch-val :ping-challenge)]
    (.execute (:cpu-bound-executor peer)
      (fn []
        (let [set-key {:sender-status sender-status
                       :creation-time creation-time
                       :peer-id (:id remote-peer)
                       :encrypted-key (rsa-encrypt! public-key
                                        (encode-aes-key encrypt-key)
                                        (:random peer))}
              signed-material (encode-set-key-signed-material set-key)
              signature (rsa-sign (:private-key peer) signed-material)
              set-key (assoc set-key :signature signature)
              encoded-set-key (encode-set-key set-key signed-material)
              iv-seed (.nextInt (:random peer))
              ping {:iv-seed iv-seed
                    :challenge challenge
                    :peer-id (:id remote-peer)}
              encoded-ping (encode-core-ping ping encrypt-key
                             (:id remote-peer))]
          (emit-messages! peer remote-peer
            [{:message-type message-type-core-set-key :bytes encoded-set-key}
             {:message-type message-type-core-ping :bytes encoded-ping}]))))))

(defn handle-set-key!
  [peer remote-peer message]
  (.execute (:cpu-bound-executor peer)
    (fn []
      (domonad maybe-m
        [public-key (deref (:public-key-atom remote-peer))
         set-key (first (parse-set-key (:bytes message)))
         :when (= (:peer-id set-key) (:id peer))
         :when (rsa-verify public-key
                 (:signed-material set-key) (:signature set-key))
         decrypted-key (rsa-decrypt (:private-key peer)
                         (:encrypted-key set-key))
         :let [decrypted-key (drop (- (count decrypted-key) aes-key-size 4)
                               decrypted-key)]
         decrypt-key (first (parse-aes-key decrypted-key))]
        (send-do-exception-m! (:state-agent remote-peer)
          [status (fetch-val :status)
           decrypt-key-created (fetch-val :decrypt-key-created)
           :when-not (and
                       (or (== status peer-status-key-received)
                         (== status peer-status-key-confirmed))
                       (.after decrypt-key-created (:creation-time set-key)))
           _ (set-val :decrypt-key decrypt-key)
           :let [creation-time (:creation-time set-key)]
           _ (update-state #(if (= decrypt-key-created creation-time)
                              %
                              (conj % {:last-sequence-number-received 0
                                       :last-packets-bitmap (int 0)
                                       :decrypt-key-created creation-time})))
           :let [sender-status (:sender-status set-key)]
           _ (update-val :status
               #(if (== % peer-status-key-confirmed)
                  %
                  peer-status-key-received))]
          (when (or (== status peer-status-down)
                  (and (not (== sender-status peer-status-key-received))
                    (not (== sender-status peer-status-key-confirmed))))
            (send-key! peer remote-peer)))))))

(defn handle-core-ping!
  [peer remote-peer message]
  (.execute (:cpu-bound-executor peer)
    (fn []
      (domonad maybe-m
        [:let [state (deref (:state-agent remote-peer))]
         decrypt-key (:decrypt-key state)
         ping (first ((parse-core-ping decrypt-key (:id peer))
                       (:bytes message)))]
        (let [bw-in (:bw-in state)
              encrypt-key (:encrypt-key state)
              iv-seed (.nextInt (:random peer))
              pong {:iv-seed iv-seed
                    :challenge (:challenge ping)
                    :inbound-bw-limit bw-in
                    :peer-id (:id peer)}
              encoded-pong (encode-core-pong pong encrypt-key
                             (:id remote-peer))]
          (emit-messages! peer remote-peer
            [{:message-type message-type-core-pong :bytes encoded-pong}]))))))

(defn handle-core-pong!
  [peer remote-peer message]
  (.execute (:cpu-bound-executor peer)
    (fn []
      (domonad maybe-m
        [:let [state (deref (:state-agent remote-peer))]
         decrypt-key (:decrypt-key state)
         :let [challenge (:ping-challenge state)]
         pong (first ((parse-core-pong decrypt-key challenge (:id peer))
                       (:bytes message)))
         :when (= (:peer-id pong) (:id remote-peer))]
        (send (:state-agent remote-peer)
          #(if (== peer-status-key-received (:status %))
             (assoc % :status peer-status-key-confirmed)
             %))))))

(defn admit-core-message!
  [peer remote-peer message]
  (if-let [dispatchers ((deref (:dispatch-agent peer))
                         (:message-type message))]
    (doseq [dispatcher! dispatchers]
      (dispatcher! peer remote-peer message))
    (.write *out* (str "No dispatcher for message type "
                    (:message-type message) "\n"))))

(defn handle-core-encrypted-message!
  [peer remote-peer message]
  (.execute (:cpu-bound-executor peer)
    (fn []
      (domonad maybe-m
        [:let [state (deref (:state-agent remote-peer))]
         decrypt-key (:decrypt-key state)
         :let [decrypt-key-created (:decrypt-key-created state)]
         message (first ((parse-core-encrypted-message decrypt-key
                           decrypt-key-created (:id peer)) (:bytes message)))]
        (send-do-exception-m! (:state-agent remote-peer)
          [last-seqnum (fetch-val :last-sequence-number-received)
           :let [seqnum (:sequence-number message)]
           :when-not (== last-seqnum seqnum)
           :when-not (> last-seqnum (+ 32 seqnum))
           bitmap (fetch-val :last-packets-bitmap)
           :let [bit (- last-seqnum seqnum 1)]
           :when-not (and (> last-seqnum seqnum) (bit-test bitmap bit))
           _ (update-state
               #(if (> last-seqnum seqnum)
                  (assoc % :last-packets-bitmap (bit-set bitmap bit))
                  (conj %
                    {:last-sequence-number-received seqnum
                     :last-packets-bitmap (.intValue
                                            (bit-shift-left (bigint bitmap)
                                              (- seqnum last-seqnum)))})))
           :when-not (.before (:timestamp message) (message-expiration))
           ;; TODO: update bandwidth tracking
           ]
          (doseq [message (:messages message)]
            (admit-core-message! peer remote-peer message)))))))

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
        (.write *out* (str "Core: " message "\n"))
        (condp = (:message-type message)
          message-type-core-set-key (handle-set-key! peer remote-peer message)
          message-type-core-encrypted-message (handle-core-encrypted-message!
                                                peer remote-peer message)
          message-type-core-ping (handle-core-ping! peer remote-peer message)
          message-type-core-pong (handle-core-pong! peer remote-peer message)
          nil)
        state))))
