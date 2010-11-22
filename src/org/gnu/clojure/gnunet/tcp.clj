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

(defn handle-disconnect!
  [peer transport encoded-address send-queue selection-key]
  (send-do-exception-m! (:sessions-agent transport)
    [sessions (fetch-state)
     :when (contains? encoded-address)
     _ (set-state (dissoc sessions encoded-address))]
    ;; Send another message to the agent to make sure no new packets have been
    ;; added to the send-queue in the mean time.
    (send (:sessions-agent transport)
      (fn [sessions]
        (.add (:selector-continuations-queue peer)
          #(do
             (doseq [packet (queue-seq! send-queue)]
               ((:continuation! packet) false))
             (.cancel selection-key)))
        (.wakeup (:selector peer))
        sessions))))

(defn handle-channel-connectable!
  [peer transport encoded-address send-queue selection-key]
  (try
    (.finishConnect (.channel selection-key))
    ;; TODO: update interestOps and send welcome
    (catch Exception e
      (handle-disconnect! peer transport encoded-address send-queue
        selection-key))))

(defn handle-channel-writable!
  [peer send-queue selection-key]
  (.add (:selector-continuations-queue peer)
    #(let [packet (.poll send-queue)]
       (if (nil? packet)
         (.interestOps selection-key SelectionKey/OP_READ)
         (try
           (let [byte-buffer (ByteBuffer/wrap (byte-array (:bytes packet)))]
             (.write (.channel selection-key) byte-buffer))
           ((:continuation! packet) true)
           (catch Exception e ((:continuation! packet) false)))))))

(defn handle-channel-selected!
  [peer transport encoded-address send-queue selection-key]
  (if (.isConnectable selection-key)
    (handle-channel-connectable! peer transport encoded-address send-queue
      selection-key))
  (if (.isReadable selection-key)
    nil)
  (if (.isWritable selection-key)
    (handle-channel-writable! peer send-queue selection-key)))


(defn new-session-from-address
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
                                (partial handle-channel-selected!
                                  peer transport encoded-address send-queue))]
            (send-do-exception-m! (:session-agent transport)
              [_ (update-val encoded-address
                   #(assoc % :selection-key selection-key))]
              nil))))
      (.wakeup (:selector peer))
      {:socket-channel socket-channel
       :remote-peer-id (:id remote-peer)
       :send-queue send-queue
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
                     (new-session-from-address peer transport remote-peer
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
