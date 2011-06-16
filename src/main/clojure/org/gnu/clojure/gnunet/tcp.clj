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
  [welcome]
  (:peer-id welcome))

(def parse-welcome
  (domonad parser-m
    [peer-id (items id-size)]
    {:peer-id peer-id}))

(defn generate-welcome-message
  [peer]
  (encode-message
    {:message-type message-type-tcp-welcome
     :bytes (encode-welcome {:peer-id (:id peer)})}))

(defn handle-disconnect!
  [peer transport encoded-address selection-key]
  ;; This is always called from inside the selector thread
  (assert-args handle-disconnect!
    (vector? encoded-address) "encoded-address as vector")
  (.cancel selection-key)
  (.close (.channel selection-key))
  (send-do-exception-m! (:sessions-agent transport)
    [remote-peer-id (with-state-field [:connection encoded-address]
                      (fetch-val :remote-peer-id))
     send-queue (fetch-val [encoded-address remote-peer-id])
     _ (update-state #(dissoc %
                        [:connection encoded-address]
                        [encoded-address remote-peer-id]))
     :when send-queue]
    (doseq [packet (queue-seq! send-queue)]
      ((:continuation! packet) false))))

(defn update-selection-key-async!
  ([peer selection-key ops]
    (.add (:selector-continuations-queue peer)
      #(try
         (.interestOps selection-key ops)
         (catch Exception e)))
    (.wakeup (:selector peer)))
  ([peer selection-key ops attachment]
    (.add (:selector-continuations-queue peer)
      #(try
         (.interestOps selection-key ops)
         (.attach selection-key attachment)
         (catch Exception e)))
    (.wakeup (:selector peer))))

(defn admit-tcp-message!
  [peer transport encoded-address selection-key message]
  (assert-args admit-tcp-message!
    (vector? encoded-address) "encoded-address as vector")
  (if (== message-type-tcp-welcome (:message-type message))
    (send-do-exception-m! (:sessions-agent transport)
      [:when-let [welcome (first (parse-welcome (:bytes message)))]
       connection (fetch-val [:connection encoded-address])
       :when-not (nil? connection)
       ;; XXX: This is weird because for an outgoing connection we don't check
       ;; that the peer-id matches who we thought we connected to.
       _ (set-val [:connection encoded-address]
           (conj connection {:remote-peer-id (:peer-id welcome)
                             :received-welcome true}))]
      (do
        (when (nil? (:remote-peer-id connection))  
          (.add (:send-queue connection)
            {:bytes (generate-welcome-message peer)
             :continuation! identity}))
        ;; We have to send again to make sure our update to the sessions-agent
        ;; is finished before updating the selection-key
        (send (:sessions-agent transport)
          (fn [sessions]
            (update-selection-key-async! peer selection-key
              (bit-or SelectionKey/OP_READ SelectionKey/OP_WRITE))
            sessions))))
    (send-do-exception-m! (:sessions-agent transport)
      [connection (fetch-val [:connection encoded-address])
       :when-let [remote-peer-id (:remote-peer-id connection)]
       :when (:received-welcome connection)
       :let [address {:transport "tcp"
                      :encoded-address encoded-address
                      :expiration (idle-connection-timeout)}]]
      (admit-message! peer remote-peer-id address message))))

(defn handle-socket-channel-connectable!
  [peer transport encoded-address selection-key]
  (.finishConnect (.channel selection-key))
  (.interestOps selection-key
    (bit-or SelectionKey/OP_READ SelectionKey/OP_WRITE)))

(defn handle-socket-channel-readable!
  [peer transport encoded-address selection-key]
  (assert-args handle-socket-channel-readable!
    (vector? encoded-address) "encoded-address as vector")
  (let [socket-channel (.channel selection-key)
        socket (.socket socket-channel)
        buffer-length (.getReceiveBufferSize socket)
        byte-buffer (doto (ByteBuffer/allocate buffer-length) (.clear))
        bytes-read (.read (.channel selection-key) byte-buffer)]
    (if (== -1 bytes-read)
      (handle-disconnect! peer transport encoded-address selection-key)
      (send-do-exception-m! (:sessions-agent transport)
        [connection (fetch-val [:connection encoded-address])
         :when-not (nil? connection)
         :let [received-bytes (concat (:received-bytes connection)
                                (buffer-seq! (.flip byte-buffer)))]
         :let [[messages residue] ((one-or-more parse-message)
                                    received-bytes)]
         :let [received-bytes (if (nil? residue) received-bytes residue)]
         _ (set-val [:connection encoded-address]
             (assoc connection :received-bytes (vec received-bytes)))]
        (doseq [message messages]
          (admit-tcp-message! peer transport encoded-address
            selection-key message))))))

(defn handle-socket-channel-writable!
  [peer transport encoded-address selection-key]
  ;; We are already in the selector thread, but add ourselves to the end of the
  ;; selector-continuations-queue because we want to make sure we set the
  ;; interest ops on the selection-key after any other continuations that might
  ;; be setting OP_WRITE.
  (assert-args handle-socket-channel-writable!
    (vector? encoded-address) "encoded-address as vector")
  (.add (:selector-continuations-queue peer)
    #(let [sessions (deref (:sessions-agent transport))]
       (when-let [connection (sessions [:connection encoded-address])]
         (let [packet (.poll (:send-queue connection))
               packet (if (nil? packet)
                        (when-let [send-queue (sessions
                                                [encoded-address
                                                 (:remote-peer-id connection)])]
                          (.poll send-queue))
                        packet)]
           (if (nil? packet)
             (.interestOps selection-key SelectionKey/OP_READ)
             (try
               (.write (.channel selection-key)
                 (ByteBuffer/wrap (byte-array (:bytes packet))))
               ((:continuation! packet) true)
               (catch Exception e
                 ((:continuation! packet) false)
                 (handle-disconnect! peer transport encoded-address
                   selection-key)))))))))

(defn handle-socket-channel-selected!
  [peer transport encoded-address selection-key]
  (try
    (if (.isConnectable selection-key)
      (handle-socket-channel-connectable! peer transport encoded-address
        selection-key))
    (if (.isReadable selection-key)
      (handle-socket-channel-readable! peer transport encoded-address
        selection-key))
    (if (.isWritable selection-key)
      (handle-socket-channel-writable! peer transport encoded-address
        selection-key))
    (catch Exception e
      (handle-disconnect! peer transport encoded-address selection-key))))

(defn set-connection-writable!
  [peer remote-peer connection]
  (when (= (:remote-peer-id connection) (:id remote-peer))
    (update-selection-key-async! peer (:selection-key connection)
      (bit-or SelectionKey/OP_READ SelectionKey/OP_WRITE))))

(defn set-connection-writable-or-connect!
  [peer transport remote-peer encoded-address]
  (assert-args set-connection-writable-or-connect!
    (vector? encoded-address) "encoded-address as vector")
  (if-let [connection ((deref (:sessions-agent transport))
                        [:connection encoded-address])]
    (set-connection-writable! peer remote-peer connection)
    (when-let [address (first (parse-address encoded-address))]
      (.add (:selector-continuations-queue peer)
        (fn []
          (let [socket-channel (doto (SocketChannel/open)
                                 (.configureBlocking false))
                selection-key (.register socket-channel (:selector peer) 0)
                send-queue (ConcurrentLinkedQueue.)]
            (send-do-exception-m! (:sessions-agent transport)
              [connection (fetch-val [:connection encoded-address])
               :when (if (nil? connection)
                       true
                       (do
                         (.cancel selection-key)
                         (set-connection-writable! peer remote-peer connection)
                         false))
               _ (set-val [:connection encoded-address]
                   {:socket-channel socket-channel
                    :selection-key selection-key
                    :send-queue send-queue
                    :remote-peer-id (:id remote-peer)
                    :received-bytes []})]
              (try
                (.connect socket-channel address)
                (.add send-queue
                  {:bytes (generate-welcome-message peer)
                   :continuation! identity})
                (update-selection-key-async! peer selection-key
                  SelectionKey/OP_CONNECT
                  (partial handle-socket-channel-selected! peer transport
                    encoded-address))
                (catch Exception e
                  (.add (:selector-continuations-queue peer)
                    #(handle-disconnect! peer transport encoded-address
                      selection-key))
                  (.wakeup (:selector peer))))))))
      (.wakeup (:selector peer)))))

(defn emit-messages-tcp!
  [peer transport remote-peer encoded-address continuation! messages]
  (assert-args emit-tcp-message!
    (vector? encoded-address) "encoded-address as vector")
  (send-do-exception-m! (:sessions-agent transport)
    [:let [continuation! #(do (emit-continuation! peer transport remote-peer
                                encoded-address %)
                            (when continuation! (continuation! %)))]
     send-queue (fetch-val [encoded-address (:id remote-peer)]
                  (ConcurrentLinkedQueue.))
     _ (set-val [encoded-address (:id remote-peer)] send-queue)]
    (do
      ;; TODO: clean up messages for sessions that are never established.
      (.add send-queue
        {:bytes (mapcat encode-message messages)
         :continuation! continuation!})
      (set-connection-writable-or-connect! peer transport remote-peer
        encoded-address))))

(defn handle-channel-acceptable!
  [peer transport server-selection-key]
  (try
    (let [socket-channel (doto (.accept (.channel server-selection-key))
                           (.configureBlocking false))
          address (.getRemoteSocketAddress (.socket socket-channel))
          encoded-address (encode-address address)
          selection-key (.register socket-channel (:selector peer) 0)]
      (send-do-exception-m! (:sessions-agent transport)
        [connection (fetch-val [:connection encoded-address])
         :when (if (nil? connection)
                 true
                 (do
                   (.cancel selection-key)
                   (.close (.channel selection-key))                   
                   false))
         _ (set-val [:connection encoded-address]
             {:socket-channel socket-channel
              :selection-key selection-key
              :send-queue (ConcurrentLinkedQueue.)
              :received-bytes []
              :incoming true})]
        (update-selection-key-async! peer selection-key SelectionKey/OP_READ
          (partial handle-socket-channel-selected! peer transport
            encoded-address))))
    (catch Exception e
      ;; If accept throws an exception, ignore it
      (do))))

(defn register-server-channel!
  [peer port]
  (let [server-channel (ServerSocketChannel/open)
        socket (.socket server-channel)
        transport {:name "tcp"
                   :emit-messages! (partial emit-messages-tcp! peer)
                   :sessions-agent (agent {})}]
    (.configureBlocking server-channel false)
    (.bind socket (InetSocketAddress. port))
    (.register server-channel (:selector peer) SelectionKey/OP_ACCEPT
      (partial handle-channel-acceptable! peer transport))
    (send (:transports-agent peer)
      #(assoc % "tcp" transport))))

(defn activate-tcp!
  [peer port]
  (.add (:selector-continuations-queue peer)
    (partial register-server-channel! peer port))
  (.wakeup (:selector peer)))
