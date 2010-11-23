(ns org.gnu.clojure.gnunet.tcp
  (:use (org.gnu.clojure.gnunet exception inet message parser peer transport
          util)
    clojure.contrib.monads)
  (:import java.net.InetSocketAddress
    (java.nio.channels SelectionKey ServerSocketChannel SocketChannel)
    java.nio.ByteBuffer
    java.util.concurrent.ConcurrentLinkedQueue))

(def message-type-tcp-welcome 60)

(defn encode-welcome
  [my-id]
  my-id)

(def parse-welcome
  (domonad parser-m [my-id (items id-size)] my-id))

(defn generate-welcome-message
  [peer]
  (encode-message
    {:message-type message-type-tcp-welcome
     :bytes (encode-welcome (:id peer))}))

(defn handle-disconnect!
  [peer transport encoded-address send-queue selection-key]
  (.write *out* (str "disconnect " encoded-address "\n"))
  (send-do-exception-m! (:sessions-agent transport)
    [sessions (fetch-state)
     :when (contains? sessions encoded-address)
     :let [_ (.write *out* (str "removing session " encoded-address "\n"))]
     _ (set-state (dissoc sessions encoded-address))]
    ;; Send another message to the agent to make sure no new packets have been
    ;; added to the send-queue in the mean time.
    (send (:sessions-agent transport)
      (fn [sessions]
        (.add (:selector-continuations-queue peer)
          #(do
             (.write *out* (str "canceling packets " send-queue "\n"))
             (doseq [packet (queue-seq! send-queue)]
               ((:continuation! packet) false))
             (.write *out* (str "closing channel " (.channel selection-key) "\n"))
             (.close (.channel selection-key))
             (.write *out* (str "canceling key " selection-key "\n"))
             (.cancel selection-key)))
        (.wakeup (:selector peer))
        sessions))))

(def handle-socket-channel-selected!)

(defn admit-tcp-message!
  [peer transport encoded-address send-queue selection-key message]
  (if (== message-type-tcp-welcome (:message-type message))
    (send-do-exception-m! (:sessions-agent transport)
      [:when-let [welcome (first (parse-welcome (:bytes message)))]
       remote-peer-id (with-state-field encoded-address
                        (fetch-val :remote-peer-id))
       :when (= remote-peer-id welcome)
       _ (with-state-field encoded-address
           (set-val :expecting-welcome false))]
      (.add (:selector-continuations-queue peer)
        #(.attach selection-key
           (partial handle-socket-channel-selected! peer transport
             encoded-address send-queue))))
    (send-do-exception-m! (:sessions-agent transport)
      [remote-peer-id (with-state-field encoded-address
                        (fetch-val :remote-peer-id))
       :let [address {:transport "tcp"
                      :encoded-address encoded-address
                      :expiration (idle-connection-timeout)}]]
      (admit-message! peer remote-peer-id address message))))

(defn handle-socket-channel-readable!
  [peer transport encoded-address send-queue selection-key]
  (let [socket-channel (.channel selection-key)
        socket (.socket socket-channel)
        buffer-length (.getReceiveBufferSize socket)
        byte-buffer (doto (ByteBuffer/allocate buffer-length) (.clear))
        bytes-read (.read (.channel selection-key) byte-buffer)]
    (if (== -1 bytes-read)
      (handle-disconnect! peer transport encoded-address send-queue
        selection-key)
      (send-do-exception-m! (:sessions-agent transport)
        [received-bytes (with-state-field encoded-address
                          (fetch-val :received-bytes))
         :let [received-bytes (concat received-bytes
                                (buffer-seq! (.flip byte-buffer)))]
         :let [[messages residue] ((one-or-more parse-message)
                                    received-bytes)]
         :let [received-bytes (if (nil? residue) received-bytes residue)]
         _ (with-state-field encoded-address
             (set-val :received-bytes (vec received-bytes)))]
        (doseq [message messages]
          (admit-tcp-message! peer transport encoded-address send-queue
            selection-key message))))))

(defn handle-socket-channel-writable!
  [peer send-queue selection-key]
  (.add (:selector-continuations-queue peer)
    #(let [packet (.poll send-queue)]
       (if (nil? packet)
         (.interestOps selection-key SelectionKey/OP_READ)
         (try
           (.write (.channel selection-key)
             (ByteBuffer/wrap (byte-array (:bytes packet))))
           ((:continuation! packet) true)
           (catch Exception e ((:continuation! packet) false)))))))

(defn handle-socket-channel-selected!
  [peer transport encoded-address send-queue selection-key]
  (try
    (if (.isReadable selection-key)
      (handle-socket-channel-readable! peer transport encoded-address send-queue
        selection-key))
    (if (.isWritable selection-key)
      (handle-socket-channel-writable! peer send-queue selection-key))
    (catch Exception e
      (handle-disconnect! peer transport encoded-address send-queue
        selection-key))))

(defn handle-connecting-channel-connectable!
  [peer transport encoded-address send-queue selection-key]
  (.finishConnect (.channel selection-key))
  (.add (:selector-continuations-queue peer)
    #(.interestOps selection-key
       (bit-or SelectionKey/OP_READ SelectionKey/OP_WRITE))))

(defn handle-connecting-channel-writable!
  [peer selection-key]
  (.write (.channel selection-key)
    (ByteBuffer/wrap (byte-array (generate-welcome-message peer))))
  (.interestOps selection-key SelectionKey/OP_READ))

(defn handle-connecting-channel-selected!
  [peer transport encoded-address send-queue selection-key]
  (try
    (if (.isConnectable selection-key)
      (handle-connecting-channel-connectable! peer transport encoded-address
        send-queue selection-key))
    (if (.isReadable selection-key)
      (handle-socket-channel-readable! peer transport encoded-address
        send-queue selection-key))
    (if (.isWritable selection-key)
      (handle-connecting-channel-writable! peer selection-key))
    (catch Exception e
      (handle-disconnect! peer transport encoded-address send-queue
        selection-key))))

(defn new-session-from-address!
  [peer transport remote-peer encoded-address]
  (when-let [address (first (parse-address encoded-address))]
    (let [socket-channel (SocketChannel/open)
          send-queue (ConcurrentLinkedQueue.)]
      (.configureBlocking socket-channel false)
      (.connect socket-channel address)
      (.add (:selector-continuations-queue peer)
        (fn []
          (let [selection-key (.register socket-channel
                                (:selector peer)
                                SelectionKey/OP_CONNECT
                                (partial handle-socket-channel-selected!
                                  peer transport encoded-address send-queue))]
            (send-do-exception-m! (:sessions-agent transport)
              [_ (with-state-field encoded-address
                   (set-val :selection-key selection-key))]
              nil))))
      (.wakeup (:selector peer))
      {:socket-channel socket-channel
       :remote-peer-id (:id remote-peer)
       :send-queue send-queue
       :received-bytes []
       :expecting-welcome true})))

(defn emit-messages-tcp!
  [peer transport remote-peer encoded-address continuation! messages]
  (doseq [message messages]
    (.write *out* (str "Send " message "\n")))
  (send-do-exception-m! (:sessions-agent transport)
    [:let [continuation! #(do (emit-continuation! peer transport remote-peer
                                encoded-address %)
                            (when continuation! (continuation! %)))]
     session (fetch-val encoded-address)
     :let [session (if (nil? session)
                     (new-session-from-address! peer transport remote-peer
                       encoded-address)
                     session)]
     :when (if (nil? session)
             (do (continuation! false)
               false)
             true)
     _ (set-val encoded-address session)]
    (do
      (.add (:send-queue session)
        {:bytes (mapcat encode-message messages)
         :continuation! continuation!})
      (when-not (:expecting-welcome session)
        (.add (:selector-continuations-queue peer)
          #(.interestOps (:selection-key session)
             (bit-or SelectionKey/OP_READ SelectionKey/OP_WRITE)))
        (.wakeup (:selector peer))))))

(defn handle-channel-acceptable!
  [peer server-channel]
  )

(defn register-server-channel!
  [peer port]
  (let [server-channel (ServerSocketChannel/open)
        socket (.socket server-channel)]
    (.configureBlocking server-channel false)
    (.bind socket (InetSocketAddress. port))
    (let [selection-key (.register server-channel
                          (:selector peer)
                          SelectionKey/OP_ACCEPT
                          (partial handle-channel-acceptable!
                            peer server-channel))]
      (send (:transports-agent peer)
        (fn [transports]
          (assoc transports "tcp"
            {:name "tcp"
             :emit-messages! (partial emit-messages-tcp! peer)
             :selection-key selection-key
             :sessions-agent (agent {})}))))))

(defn activate-tcp!
  [peer port]
  (.add (:selector-continuations-queue peer)
    (partial register-server-channel! peer port))
  (.wakeup (:selector peer)))
