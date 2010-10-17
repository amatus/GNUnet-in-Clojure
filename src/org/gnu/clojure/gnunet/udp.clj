(ns org.gnu.clojure.gnunet.udp
  (:use (org.gnu.clojure.gnunet inet parser message peer transport util)
    clojure.contrib.monads)
  (:import (java.util Date Calendar)
    (java.net InetSocketAddress DatagramPacket)
    (java.nio.channels DatagramChannel SelectionKey)
    java.nio.ByteBuffer
    java.util.concurrent.ConcurrentLinkedQueue))

(def max-udp-packet-length 65536)
(def message-type-udp 0)

(defn encode-udp
  [udp]
  (concat
    (:sender-id udp)
    (mapcat encode-message (:messages udp))))

(def parse-udp
  (domonad parser-m [sender-id (items id-size)
                     messages (none-or-more parse-message)]
    {:sender-id sender-id :messages messages}))

(defn generate-udp-message
  [peer messages]
  (encode-message
    {:message-type message-type-udp
     :bytes (encode-udp
              {:sender-id (:id peer) :messages messages})}))

(defn configure-udp-addresses!
  "Adds new addresses for the udp transport to peer's transports-agent and
   removes expired addresses." 
  [peer reachable-addresses port]
  (send (:transport-addresses-agent peer)
    (fn [addresses]
      (merge-transport-addresses {}
        (expire-transport-addresses (Date.)
          (concat (list-transport-addresses addresses)
            (for [address reachable-addresses]
              {:transport "udp"
               :encoded-address (encode-address (InetSocketAddress. address
                                                  port))
               :expiration (hello-address-expiration)})))))))

(defn emit-continuation!
  [peer transport remote-peer encoded-address result]
  (if result
    (send (:state-agent remote-peer)
      (fn [state]
        (conj state {:is-connected true
                     :connected-transport transport
                     :connected-address encoded-address})))))

(defn emit-messages-udp!
  [peer transport remote-peer encoded-address continuation! messages]
  (if-let [address (first (parse-address encoded-address))]
    (let [continuation! #(do
                           (emit-continuation! peer transport remote-peer
                             encoded-address %)
                           (continuation! %))] 
      (.add (:send-queue transport)
        {:bytes (generate-udp-message peer messages)
         :address address
         :continuation! continuation!})
      (.add (:selector-continuations-queue peer)
        #(.interestOps (:selection-key transport)
           (bit-or SelectionKey/OP_READ SelectionKey/OP_WRITE)))
      (.wakeup (:selector peer)))
    (when continuation! (continuation! false))))

(defn handle-channel-writable!
  [peer datagram-channel]
  (let [transport ((deref (:transports-agent peer)) "udp")]
    (.add (:selector-continuations-queue peer)
      #(let [packet (.poll (:send-queue transport))]
         (if (not (nil? packet))
           (try
             (let [byte-buffer (ByteBuffer/wrap (byte-array (:bytes packet)))]
               (.send datagram-channel byte-buffer (:address packet)))
             ((:continuation! packet) true)
             (catch Exception e ((:continuation! packet) false)))
           (.interestOps (:selection-key transport) SelectionKey/OP_READ))))))

(defn handle-channel-readable!
  [peer datagram-channel]
  (let [byte-buffer (doto (ByteBuffer/allocate max-udp-packet-length) (.clear))
        source-address (.receive datagram-channel byte-buffer)
        address {:transport "udp"
                 :encoded-address (encode-address source-address)
                 :expiration (idle-connection-timeout)}]
    (.flip byte-buffer)
    (when-let [{udp :message} (first ((parse-message-types
                                        {message-type-udp parse-udp})
                                       (buffer-seq! byte-buffer)))]
      (if (not (= (:sender-id udp) (:id peer)))
        (doseq [message (:messages udp)]
          (admit-message! peer (:sender-id udp) address message))))))

(defn handle-channel-selected!
  [peer datagram-channel selection-key]
  (if (.isReadable selection-key)
    (handle-channel-readable! peer datagram-channel))
  (if (.isWritable selection-key)
    (handle-channel-writable! peer datagram-channel)))

(defn register-datagram-channel!
  [peer port]
  (let [datagram-channel (DatagramChannel/open)
        socket (.socket datagram-channel)]
    (.configureBlocking datagram-channel false)
    (.bind socket (InetSocketAddress. port))
    (let [selection-key (.register datagram-channel
                          (:selector peer)
                          SelectionKey/OP_READ
                          (partial handle-channel-selected!
                            peer datagram-channel))]
      (send (:transports-agent peer)
        (fn [transports]
          (assoc transports "udp"
            {:emit-messages! (partial emit-messages-udp! peer)
             :socket socket
             :selection-key selection-key
             :send-queue (ConcurrentLinkedQueue.)}))))))

(defn activate-udp!
  [peer port]
  (.add (:selector-continuations-queue peer)
    (partial register-datagram-channel! peer port))
  (.wakeup (:selector peer)))
