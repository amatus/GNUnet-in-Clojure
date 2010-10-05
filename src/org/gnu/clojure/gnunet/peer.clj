(ns org.gnu.clojure.gnunet.peer
  (:use (org.gnu.clojure.gnunet crypto message))
  (:import java.nio.channels.Selector))

(defstruct remote-peer
  ;; java.security.PublicKey
  :public-key
  
  ;; 64 byte (512-bit) sequence
  :id
  
  ;; agent of a map associating transport names (strings) to maps associating
  ;; transport addresses (byte vector) to maps containing {:expiration
  ;; (java.util.Date) :latency (int, if ever connected)}
  :transport-addresses-agent
  
  ;; agent of a map of {:transport (map from peer:transports-agent, if
  ;; connection is in progress) :transport-name (String)}
  :connection-agent)

(def peer (apply create-struct (concat
  (keys (struct-map remote-peer))
  (list
    ;; java.security.PrivateKey
    :private-key
    
    ;; agent of a map of peer IDs to struct remote-peer
    :remote-peers-agent
    
    ;; agent of a map of transport names (String) to maps of {:connect!
    ;; :emit-message!}
    :transports-agent
    
    ;; java.nio.channels.Selector
    :selector
    
    ;; Thread which selects on :selector
    :selector-thread))))

(defstruct peer-options
  :keypair)

(defn generate-id
  "Generate the SHA-512 digest of the encoded public key."
  [public-key]
  (sha-512 (encode-rsa-public-key public-key)))

(def id-size (count (sha-512 ())))

(defn selector-loop
  [selector]
  (.select selector)
  (let [selected-keys (.selectedKeys selector)]
    (for [selection-key (enumeration-seq (.iterator selected-keys))]
      ((.attachment selection-key)))
    (.clear selected-keys))
  (recur selector))

(defn new-peer [options]
  (let [selector (Selector/open)]
    (struct-map peer
      :public-key (.getPublic (:keypair options))
      :id (generate-id (.getPublic (:keypair options)))
      :transport-addresses-agent (agent {})
      :private-key (.getPrivate (:keypair options))
      :remote-peers-agent (agent {})
      :transports-agent (agent nil)
      :selector selector
      :selector-thread (Thread. (partial selector-loop selector))))
