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
  [peer]
  (:id peer))

(def parse-welcome
  (domonad parser-m
    [id (items id-size)]
    {:id id}))

(defn generate-welcome-message
  [peer]
  (encode-message
    {:message-type message-type-tcp-welcome
     :bytes (encode-welcome peer)}))

(defn handle-disconnect!
  [peer transport connection]
  ;; This is always called from inside the selector thread
  (.cancel (:selection-key connection))
  (.close (:socket-channel connection))
  (send-do-exception-m!
    (:connections-agent transport)
    [pending-connections (fetch-val nil (hash-set))
     _ (set-val nil (disj pending-connections connection))
     :when-let [remote-peer-id (deref (:remote-peer-id-atom connection))]
     remote-peer-connections (fetch-val remote-peer-id)
     _ (set-val remote-peer-id (disj remote-peer-connections connection))]
    nil))

(defn update-selection-key!
  [selection-key ops & attachment]
  ;; This is always called from inside the selector thread
  (try
    (.interestOps selection-key ops)
    (when attachment (.attach selection-key (first attachment)))
    (catch Exception e)))

(defn update-selection-key-async!
  [peer selection-key ops & attachment]
  (.add (:selector-callbacks-queue peer)
        #(apply update-selection-key! selection-key ops attachment))
  (.wakeup (:selector peer)))

(defn admit-tcp-message!
  [peer transport connection message]
  ;; This is always called from inside the selector thread
  (if (== message-type-tcp-welcome (:message-type message))
    (domonad
      exception-m
      [:when-let [welcome (first (parse-welcome (:bytes message)))]
       :let [remote-peer-id (:peer-id welcome)]
       :when-not (== remote-peer-id (:id peer))
       :when (nil? (deref (:remote-peer-id-atom connection)))]
      (let [remote-peer-id (:peer-id welcome)]
        (swap! (:remote-peer-id-atom connection)
               (fn [_] remote-peer-id))
        (.add (:send-queue connection)
              {:bytes (generate-welcome-message peer)
               :callback! skip})
        (update-selection-key!
          (:selection-key connection)
          (bit-or SelectionKey/OP_READ SelectionKey/OP_WRITE))
        (send-do-exception-m!
          (:connections-agent transport)
          [pending-connections (fetch-val nil)
           _ (set-val nil (disj pending-connections connection))
           remote-peer-connections (fetch-val remote-peer-id (hash-set))
           _ (set-val remote-peer-id (conj remote-peer-connections
                                           connection))]
          nil)))
    (when-let [remote-peer-id (deref (:remote-peer-id-atom connection))]
      (let [address {:transport "tcp"
                     :encoded-address (:encoded-address connection)
                     :expiration (idle-connection-timeout)}]
        (admit-message! peer remote-peer-id address message)))))

(defn handle-socket-channel-connectable!
  [peer transport connection]
  ;; This is always called from inside the selector thread
  (.finishConnect (:socket-channel connection))
  (.interestOps (:selection-key connection)
    (bit-or SelectionKey/OP_READ SelectionKey/OP_WRITE)))

(defn handle-socket-channel-readable!
  [peer transport connection]
  ;; This is always called from inside the selector thread
  (let [socket-channel (:socket-channel connection)
        socket (.socket socket-channel)
        buffer-length (.getReceiveBufferSize socket)
        byte-buffer (doto (ByteBuffer/allocate buffer-length) (.clear))
        bytes-read (.read socket-channel byte-buffer)]
    (if (== -1 bytes-read)
      (handle-disconnect! peer transport connection)
      ;; NB: parse-message will only fail on an incomplete message and
      ;; there is a maximum message size.
      ;; Therefore received-bytes is bounded by the maximum message size.
      ;; If, for example, there were some checksum that it verified then
      ;; received-bytes could grow without bound having an invalid message
      ;; stuck in the buffer.
      (let [received-bytes (concat (deref (:received-bytes-atom connection))
                                   (buffer-seq! (.flip byte-buffer)))
            [messages residue] ((one-or-more parse-message) received-bytes)
            received-bytes (if (nil? residue) received-bytes residue)]
        (swap! (:received-bytes-atom connection)
               (fn [_] received-bytes))
        (doseq [message messages]
          (admit-tcp-message! peer transport connection message))))))

(defn handle-socket-channel-writable!
  [peer transport connection]
  ;; We are already in the selector thread, but add ourselves to the end of the
  ;; selector-callbacks-queue because we want to make sure we set the
  ;; interest ops on the selection-key after any other callbacks that might
  ;; be setting OP_WRITE.
  (.add (:selector-callbacks-queue peer)
    #(let [packet (.poll (:send-queue connection))
           remote-peer-id (deref (:remote-peer-id-atom connection))
           packet (if (and (not (nil? remote-peer-id)) (nil? packet))
                    (.poll ((deref (:sessions-agent transport)) remote-peer-id))
                    packet)]
       (if (nil? packet)
         (.interestOps (:selection-key connection) SelectionKey/OP_READ)
         (try
           (.write (:socket-channel connection)
                   (ByteBuffer/wrap (byte-array (:bytes packet))))
           ((:callback! packet) true)
           (catch Exception e
             ((:callback! packet) false)
             (handle-disconnect! peer transport connection)))))))

(defn handle-socket-channel-selected!
  [peer transport connection]
  ;; This is always called from inside the selector thread
  (let [selection-key (:selection-key connection)]
    (try
      (when (.isConnectable selection-key)
        (handle-socket-channel-connectable! peer transport connection))
      (when (.isReadable selection-key)
        (handle-socket-channel-readable! peer transport connection))
      (when (.isWritable selection-key)
        (handle-socket-channel-writable! peer transport connection))
      (catch Exception e
        (handle-disconnect! peer transport connection)))))

(defn connect!
  [peer transport remote-peer encoded-address]
  (when-let [address (first (parse-address encoded-address))]
    (.add (:selector-callbacks-queue peer)
      (fn []
        (let [socket-channel (doto (SocketChannel/open)
                               (.configureBlocking false))
              selection-key (.register socket-channel (:selector peer) 0)
              remote-peer-id (:id remote-peer)
              send-queue (ConcurrentLinkedQueue.)
              connection {:socket-channel socket-channel
                          :encoded-address encoded-address
                          :selection-key selection-key
                          :send-queue send-queue
                          :received-bytes-atom (atom nil)
                          :remote-peer-id-atom (atom remote-peer-id)}]
          (.add send-queue
                {:bytes (generate-welcome-message peer)
                 :callback! skip})
          (update-selection-key!
            selection-key
            SelectionKey/OP_CONNECT
            (partial handle-socket-channel-selected! peer transport connection))
          (try
            (.connect socket-channel address)
            (catch Exception e
              (handle-disconnect! peer transport connection)))
          (send
            (:connections-agent transport)
            conj-vals
            (hash-set)
            [remote-peer-id connection]))))
    (.wakeup (:selector peer))))

(defn set-write-interest-or-connect!
  [peer transport remote-peer encoded-address]
  (if-let [remote-peer-connections ((deref (:connections-agent transport))
                                      (:id remote-peer))]
    (update-selection-key-async!
      peer
      (:selection-key (first remote-peer-connections))
      (bit-or SelectionKey/OP_CONNECT
              SelectionKey/OP_READ
              SelectionKey/OP_WRITE))
    (connect! peer transport remote-peer encoded-address)))

(defn enqueue-messages!
  [peer transport remote-peer encoded-address callback! messages send-queue]
  ;; TODO: clean up messages for sessions that are never established.
  (.add send-queue
    {:bytes (mapcat encode-message messages)
     :callback! callback!})
  (set-write-interest-or-connect! peer transport remote-peer
    encoded-address))

(defn emit-messages-tcp!
  [peer transport remote-peer encoded-address callback! messages]
  (assert-args emit-messages-tcp!
    (vector? encoded-address) "encoded-address as vector")
  (let [callback! #(do (emit-callback! peer transport remote-peer
                                       encoded-address %)
                     (when callback! (callback! %)))
        enqueue! (partial enqueue-messages! peer transport remote-peer
                          encoded-address callback! messages)
        remote-peer-id (:id remote-peer)
        send-queue ((deref (:sessions-agent transport)) remote-peer-id)]
    (if (nil? send-queue)
      (send-do-exception-m!
        (:sessions-agent transport)
        [send-queue (fetch-val remote-peer-id (ConcurrentLinkedQueue.))
         _ (set-val remote-peer-id send-queue)]
        (enqueue! send-queue))
      (enqueue! send-queue))))

(defn handle-channel-acceptable!
  [peer transport server-socket-channel]
  ;; This is always called from inside the selector thread
  (try
    (let [socket-channel (doto (.accept server-socket-channel)
                           (.configureBlocking false))
          address (.getRemoteSocketAddress (.socket socket-channel))
          encoded-address (encode-address address)
          selection-key (.register socket-channel (:selector peer) 0)
          connection {:socket-channel socket-channel
                      :encoded-address encoded-address
                      :selection-key selection-key
                      :send-queue (ConcurrentLinkedQueue.)
                      :received-bytes-atom (atom nil)
                      :remote-peer-id-atom (atom nil)
                      :incoming true}]
      (update-selection-key!
        selection-key
        SelectionKey/OP_READ
        (partial handle-socket-channel-selected! peer transport connection))
      (send
        (:connections-agent transport)
        conj-vals
        (hash-set)
        [nil connection]))
    (catch Exception e nil)))

(defn register-server-channel!
  [peer port]
  ;; This is always called from inside the selector thread
  (let [server-socket-channel (ServerSocketChannel/open)
        socket (.socket server-socket-channel)
        transport {:name "tcp"
                   :emit-messages! (partial emit-messages-tcp! peer)
                   :connections-agent (agent {})
                   :sessions-agent (agent {})}]
    (.configureBlocking server-socket-channel false)
    (.bind socket (InetSocketAddress. port))
    (.register server-socket-channel (:selector peer) SelectionKey/OP_ACCEPT
      (partial handle-channel-acceptable! peer transport server-socket-channel))
    (send (:transports-agent peer)
      #(assoc % "tcp" transport))))

(defn activate-tcp!
  [peer port]
  (.add (:selector-callbacks-queue peer)
    (partial register-server-channel! peer port))
  (.wakeup (:selector peer)))
