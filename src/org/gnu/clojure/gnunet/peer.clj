(ns org.gnu.clojure.gnunet.peer
  (:use (org.gnu.clojure.gnunet identity)))

(defstruct remote-peer
  :public-key         ;; java.security.PublicKey
  :id                 ;; 64 byte (512-bit) sequence
  :transports-agent)  ;; agent of a map associating transport names (strings) to
                      ;; maps associating transport addresses (usually
                      ;; java.net.InetSocketAddress) to expiration times
                      ;; (java.util.Date)

(defn new-remote-peer-from-hello
  [hello]
  (struct-map remote-peer
    :public-key (:public-key hello)
    :id (generate-id (:public-key hello))
    :transports-agent (agent (:transports hello))))

(def peer (apply create-struct (concat
  (keys (struct-map remote-peer))
  (list
    :private-key            ;; java.security.PrivateKey
    :remote-peers-agent)))) ;; agent of a map of peer IDs to struct remote-peer

(defstruct peer-options
  :keypair)

(defn new-peer [options]
  (struct-map peer
    :public-key (.getPublic (:keypair options))
    :id (generate-id (.getPublic (:keypair options)))
    :transports-agent (agent {})
    :private-key (.getPrivate (:keypair options))
    :remote-peers-agent (agent {})))
