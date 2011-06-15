(ns org.gnu.clojure.gnunet.udp
  (:use (org.gnu.clojure.gnunet inet parser message peer transport util)
    clojure.contrib.monads)
  (:import java.net.InetSocketAddress
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

(defn emit-messages-udp!
  [peer transport remote-peer encoded-address continuation! messages]
  ;;(doseq [message messages]
  ;;  (.write *out* (str "Send " message "\n")))
  (if-let [address (first (parse-address encoded-address))]
    (let [continuation! #(do
                           (emit-continuation! peer transport remote-peer
                             encoded-address %)
                           (when continuation! (continuation! %)))] 
      (.add (:send-queue transport)
        {:bytes (generate-udp-message peer messages)
         :address address
         :continuation! continuation!})
      (.add (:selector-continuations-queue peer)
        #(.interestOps (:selection-key transport)
           (bit-or SelectionKey/OP_READ SelectionKey/OP_WRITE)))
      (.wakeup (:selector peer)))
    (when continuation! (continuation! false))))

(defn handle-datagram-channel-writable!
  [peer datagram-channel]
  (let [transport ((deref (:transports-agent peer)) "udp")]
    (.add (:selector-continuations-queue peer)
      #(let [packet (.poll (:send-queue transport))]
         (if (nil? packet)
           (.interestOps (:selection-key transport) SelectionKey/OP_READ)
           (try
             (let [byte-buffer (ByteBuffer/wrap (byte-array (:bytes packet)))]
               (.send datagram-channel byte-buffer (:address packet)))
             ((:continuation! packet) true)
             (catch Exception e ((:continuation! packet) false))))))))

(defn handle-datagram-channel-readable!
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
      (when-not (= (:sender-id udp) (:id peer))
        (doseq [message (:messages udp)]
          (admit-message! peer (:sender-id udp) address message))))))

(defn handle-datagram-channel-selected!
  [peer datagram-channel selection-key]
  (if (.isReadable selection-key)
    (handle-datagram-channel-readable! peer datagram-channel))
  (if (.isWritable selection-key)
    (handle-datagram-channel-writable! peer datagram-channel)))

(defn register-datagram-channel!
  [peer port]
  (let [datagram-channel (DatagramChannel/open)
        socket (.socket datagram-channel)]
    (.configureBlocking datagram-channel false)
    (.bind socket (InetSocketAddress. port))
    (let [selection-key (.register datagram-channel
                          (:selector peer)
                          SelectionKey/OP_READ
                          (partial handle-datagram-channel-selected!
                            peer datagram-channel))]
      (send (:transports-agent peer)
        (fn [transports]
          (assoc transports "udp"
            {:name "udp"
             :emit-messages! (partial emit-messages-udp! peer)
             :selection-key selection-key
             :send-queue (ConcurrentLinkedQueue.)}))))))

(defn activate-udp!
  [peer port]
  (.add (:selector-continuations-queue peer)
    (partial register-datagram-channel! peer port))
  (.wakeup (:selector peer)))
