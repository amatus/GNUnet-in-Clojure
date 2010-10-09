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
  "Adds new addresses for the udp transport to peer's transports-agent expiring
   in 12 hours and removes expired addresses." 
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
               :expiration (.getTime (doto (Calendar/getInstance)
                                       (.add Calendar/HOUR_OF_DAY 12)))})))))))

(defn emit-messages-udp!
  [peer transport encoded-address messages]
  (let [address (first (parse-address encoded-address))]
    (.add (:send-queue transport)
      {:bytes (generate-udp-message peer messages)
       :address address})
    (.add (:selector-continuations-queue peer)
      #(.interestOps (:selection-key transport)
         (bit-or SelectionKey/OP_READ SelectionKey/OP_WRITE)))
    (.wakeup (:selector peer))))

(defn handle-channel-writable!
  [peer datagram-channel]
  (let [transport ((deref (:transports-agent peer)) "udp")]
    (.add (:selector-continuations-queue peer)
      #(let [packet (.poll (:send-queue transport))]
         (if (not (nil? packet))
           (let [byte-buffer (ByteBuffer/wrap (byte-array (:bytes packet)))]
             (.send datagram-channel byte-buffer (:address packet)))
           (.interestOps (:selection-key transport) SelectionKey/OP_READ))))))

(defn handle-channel-readable!
  [peer datagram-channel]
  (let [byte-buffer (doto (ByteBuffer/allocate max-udp-packet-length) (.clear))
        source-address (.receive datagram-channel byte-buffer)]
    (.flip byte-buffer)
    (when-let [{udp :message} (first ((parse-message-types
                                        {message-type-udp parse-udp})
                                       (buffer-seq! byte-buffer)))]
      (if (not (= (:sender-id udp) (seq (:id peer))))
        (doseq [message (:messages udp)]
          (admit-message! peer (:sender-id udp) source-address message))))))

(defn handle-channel-selected!
  [peer datagram-channel selection-key]
  (if (.isReadable selection-key)
    (handle-channel-readable! peer datagram-channel))
  (if (.isWritable selection-key)
    (handle-channel-writable! peer datagram-channel)))

(defn connect-udp!
  [peer remote-peer address]
  {:message-queue (ConcurrentLinkedQueue.)})

(defn- register-datagram-channel!
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
            {:connect! (partial connect-udp! peer)
             :emit-messages! (partial emit-messages-udp! peer)
             :socket socket
             :selection-key selection-key
             :send-queue (ConcurrentLinkedQueue.)}))))))

(defn activate-udp!
  [peer port]
  (.add (:selector-continuations-queue peer)
    (partial register-datagram-channel! peer port))
  (.wakeup (:selector peer)))
