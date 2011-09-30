(ns org.gnu.clojure.gnunet.peer
  (:use (org.gnu.clojure.gnunet crypto message util))
  (:import java.nio.channels.Selector
    (java.util.concurrent ConcurrentLinkedQueue LinkedBlockingQueue
      PriorityBlockingQueue ScheduledThreadPoolExecutor ThreadPoolExecutor
      TimeUnit)
    java.security.SecureRandom))

(defstruct remote-peer-struct
  ;; atom of java.security.PublicKey
  :public-key-atom
  
  ;; vector of 64 bytes (512 bits)
  :id
  
  ;; agent of a map associating transport names (String) to maps associating
  ;; transport addresses (byte vector) to maps containing {:expiration
  ;; (java.util.Date) :latency (int, if validated)}
  :transport-addresses-agent
  
  ;; agent of a map of state.
  ;; Remote-peers:
  ;; { (shared between layers)
  ;;  :is-connected (boolean)
  ;;  :connected-transport (value from peer-struct:transports-agent)
  ;;  :connected-address (byte vector)
  ;;   (core layer)
  ;;  :status (int)
  ;;  :decrypt-key-created (java.util.Date)
  ;;  :encrypt-key (java.security.Key)
  ;;  :encrypt-key-created (java.util.Date)
  ;;  :ping-challenge (int)
  ;;  :bw-in (int)
  ;;  :last-sequence-number-sent (int)
  ;;   (filesharing layer)
  ;;  :trust (int)
  ;;  :average-priority (float)
  ;; }
  ;; Local peer:
  ;; { (filesharing layer)
  ;;  :queries (map of query hashes to maps of return-to peer ids to queries)
  ;;  :ttl-queue (java.util.PriorityQueue of [query return-to] pairs sorted by
  ;;              :ttl stored in metadata)
  ;; }
  :state-agent)

(def peer-struct (apply create-struct (concat
  (keys (struct-map remote-peer-struct))
  (list
    ;; java.security.PrivateKey
    :private-key
    
    ;; agent of a map of peer IDs to struct remote-peer
    :remote-peers-agent
    
    ;; agent of a map of transport names (String) to maps of {:emit-messages!}
    :transports-agent
    
    ;; {
    ;;  :new-peer-callbacks
    ;;  :peer-changed-callbacks
    ;;  :new-address-callbacks
    ;;  :address-changed-callbacks
    ;; }
    :topology-agent

    ;; agent of a map of message types to sets of dispatch handlers
    :dispatch-agent
    
    ;; java.nio.channels.Selector
    :selector
    
    ;; Thread which selects on :selector
    :selector-thread
    
    ;; java.util.concurrent.ConcurrentLinkedQueue of callbacks.
    ;; In order to access the selector while the selector-thread is running add
    ;; a callback to this queue and call .wakeup on the selector.
    ;; The size of this queue is an easy measure our network load.
    :selector-callbacks-queue
    
    ;; java.security.SecureRandom
    :random
    
    ;; java.util.concurrent.ThreadPoolExecutor for executing CPU-bound
    ;; operations like generating RSA keys, hashes, etc. It has one thread for
    ;; each processor in the system and a "practically" unbounded FIFO queue.
    :cpu-bound-executor
    
    ;; java.util.concurrent.LinkedBlockingQueue of Integer.MAX_VALUE capacity.
    ;; The size of this queue is an easy measure of our CPU load.
    :cpu-bound-queue
    
    ;; java.util.concurrent.ThreadPoolExecutor for executing disk-bound
    ;; operations like quering a database or reading/writing files. It has a
    ;; single thread and an unbounded priority queue. The priority of a callable
    ;; object is stored in its metadata under the key :priority.
    :disk-bound-executor
    
    ;; java.util.concurrent.PriorityBlockingQueue of unbounded capacity.
    ;; The size of this queue is an easy measure of our disk load.
    :disk-bound-queue
    
    ;; agent of a map of Strings to Numbers.
    :metrics-agent
    
    ;; java.util.concurrent.ScheduledThreadPoolExecutor
    :scheduled-executor))))

(defn generate-id
  "Generate the SHA-512 digest of the encoded public key."
  [public-key]
  (vec (sha-512 (encode-rsa-public-key public-key))))

(def id-size hash-size)

(def priority-comparator
  (reify java.util.Comparator
    (compare [this o1 o2]
      (clojure.core/compare (:priority (meta o2)) (:priority (meta o1))))
    (equals [this obj]
      (== (:priority (meta this)) (:priority (meta obj))))))

(defn selector-loop!
  [selector callbacks]
  (do-callbacks! (queue-seq! callbacks))
  (.select selector)
  (let [selected-keys (.selectedKeys selector)]
    (do-callbacks! (map #(.attachment %) selected-keys))
    (.clear selected-keys))
  (recur selector callbacks))

(defn new-peer [options]
  (let [selector (Selector/open)
        callbacks (ConcurrentLinkedQueue.)
        cpu-bound-queue (LinkedBlockingQueue.)
        cpu-bound-executor (ThreadPoolExecutor. 0 (available-processors) 60
                             TimeUnit/SECONDS cpu-bound-queue)
        disk-bound-queue (PriorityBlockingQueue. 1 priority-comparator)
        disk-bound-executor (ThreadPoolExecutor. 0 1 60 TimeUnit/SECONDS
                              disk-bound-queue)]
    (struct-map peer-struct
      :public-key-atom (atom (:public-key options))
      :id (generate-id (:public-key options))
      :transport-addresses-agent (agent {})
      :state-agent (agent {})
      :private-key (:private-key options)
      :remote-peers-agent (agent {})
      :transports-agent (agent {})
      :topology-agent (agent {})
      :dispatch-agent (agent {})
      :selector selector
      :selector-thread (Thread. (partial selector-loop! selector callbacks))
      :selector-callbacks-queue callbacks
      :random (:random options)
      :cpu-bound-executor cpu-bound-executor
      :cpu-bound-queue cpu-bound-queue
      :disk-bound-executor disk-bound-executor
      :disk-bound-queue disk-bound-queue
      :metrics-agent (agent {})
      :scheduled-executor (ScheduledThreadPoolExecutor. 1))))

(defn network-load
  [peer]
  ;; TODO: figure out if we really need size, it's an O(n) operation
  (.size (:selector-callbacks-queue peer)))

(defn cpu-load
  [peer]
  (.size (:cpu-bound-queue peer)))

(defn disk-load
  [peer]
  (.size (:disk-bound-queue peer)))
