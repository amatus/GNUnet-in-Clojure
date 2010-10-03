(ns org.gnu.clojure.gnunet.peer
  (:use (org.gnu.clojure.gnunet crypto message)))

(defstruct remote-peer
  ;; java.security.PublicKey
  :public-key
  
  ;; 64 byte (512-bit) sequence
  :id
  
  ;; agent of a map associating transport names (strings) to maps associating
  ;; transport addresses (byte vector) to maps containing {:expiration
  ;; (java.util.Date) :latency (int, if ever connected)}
  :transports-agent
  
  ;; agent of ??
  :connection-agent)

(def peer (apply create-struct (concat
  (keys (struct-map remote-peer))
  (list
    ;; java.security.PrivateKey
    :private-key
    
    ;; agent of a map of peer IDs to struct remote-peer
    :remote-peers-agent))))

(defstruct peer-options
  :keypair)

(defn generate-id
  "Generate the SHA-512 digest of the encoded public key."
  [public-key]
  (sha-512 (encode-rsa-public-key public-key)))

(def id-size (count (sha-512 ())))

(defn new-peer [options]
  (struct-map peer
    :public-key (.getPublic (:keypair options))
    :id (generate-id (.getPublic (:keypair options)))
    :transports-agent (agent {})
    :private-key (.getPrivate (:keypair options))
    :remote-peers-agent (agent {})))
