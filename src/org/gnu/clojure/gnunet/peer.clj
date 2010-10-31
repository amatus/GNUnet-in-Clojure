(ns org.gnu.clojure.gnunet.peer
  (:use (org.gnu.clojure.gnunet crypto message util))
  (:import java.nio.channels.Selector
    java.util.concurrent.ConcurrentLinkedQueue
    java.security.SecureRandom))

(defstruct remote-peer-struct
  ;; atom of java.security.PublicKey
  :public-key-atom
  
  ;; 64 byte (512-bit) vector
  :id
  
  ;; agent of a map associating transport names (String) to maps associating
  ;; transport addresses (byte vector) to maps containing {:expiration
  ;; (java.util.Date) :latency (int, if validated)}
  :transport-addresses-agent
  
  ;; agent of a map of state (nil for local peer?)
  ;; { (shared between layers)
  ;;  :is-connected (boolean)
  ;;  :connected-transport (value from peer-struct:transports-agent)
  ;;  :connected-address (byte vector)
  ;;   (core layer)
  ;;  :status peer-status-down (int)
  ;;  :decrypt-key-created (java.util.Date)
  ;;  :encrypt-key (java.security.Key)
  ;;  :encrypt-key-created (java.util.Date)
  ;;  :ping-challenge (int)
  ;;  :bw-in (int) }
  :state-agent)

(def peer-struct (apply create-struct (concat
  (keys (struct-map remote-peer-struct))
  (list
    ;; java.security.PrivateKey
    :private-key
    
    ;; agent of a map of peer IDs to struct remote-peer
    :remote-peers-agent
    
    ;; agent of a map of transport names (String) to maps of {:emit-message!}
    :transports-agent
    
    ;; java.nio.channels.Selector
    :selector
    
    ;; Thread which selects on :selector
    :selector-thread
    
    ;; java.util.concurrent.ConcurrentLinkedQueue of continuations, in order to
    ;; access the selector while the selector-thread is running add a
    ;; continuation to this queue and call .wakeup on the selector
    :selector-continuations-queue
    
    ;; java.security.SecureRandom
    :random))))

(defstruct peer-options
  :keypair)

(defn generate-id
  "Generate the SHA-512 digest of the encoded public key."
  [public-key]
  (vec (sha-512 (encode-rsa-public-key public-key))))

(def id-size hash-size)

(defn selector-loop!
  [selector continuations]
  (doseq [continuation (queue-seq! continuations)]
    (continuation))
  (.select selector)
  (let [selected-keys (.selectedKeys selector)]
    (doseq [selection-key selected-keys]
      ((.attachment selection-key) selection-key))
    (.clear selected-keys))
  (recur selector continuations))

(defn new-peer [options]
  (let [selector (Selector/open)
        continuations (ConcurrentLinkedQueue.)]
    (struct-map peer-struct
      :public-key-atom (atom (.getPublic (:keypair options)))
      :id (generate-id (.getPublic (:keypair options)))
      :transport-addresses-agent (agent {})
      :private-key (.getPrivate (:keypair options))
      :remote-peers-agent (agent {})
      :transports-agent (agent nil)
      :selector selector
      :selector-thread (Thread. (partial selector-loop! selector continuations))
      :selector-continuations-queue continuations
      :random (:random options))))
