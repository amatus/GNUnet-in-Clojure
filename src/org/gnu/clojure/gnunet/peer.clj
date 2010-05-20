(ns org.gnu.clojure.gnunet.peer
  (:use (org.gnu.clojure.gnunet identity))
  (:import java.util.Date))

(defstruct remote-peer
  :public-key
  :id
  :transports-agent)

(defn new-remote-peer-from-hello
  [hello]
  (struct-map remote-peer
    :public-key (:public-key hello)
    :id (generate-id (:public-key hello))
    :transports-agent (agent (:transports hello))))

(def peer (apply create-struct (concat
  (keys (struct-map remote-peer))
  (list
    :private-key
    :remote-peers-agent))))

(defstruct peer-options
  :keypair)

(defn new-peer [options]
  (struct-map peer
    :public-key (.getPublic (:keypair options))
    :id (generate-id (.getPublic (:keypair options)))
    :transports-agent (agent [])
    :private-key (.getPrivate (:keypair options))
    :remote-peers-agent (agent {})))

(def filter-expired-transports
  (partial filter #(< (:expiration %) (Date.))))

;; Event - Peer receives a HELLO message
(defn admit-hello!
  [peer hello]
  (letfn [(update-transports
            [transports new-transports]
            (filter-expired-transports (concat transports new-transports)))
          (update-remote-peers
            [remote-peers hello]
            (let [id (vec (generate-id (:public-key hello)))
                  remote-peer (remote-peers id)]
              (if remote-peer
                (do
                  (send
                    (:transports-agent remote-peer)
                    update-transports
                    (:transports hello))
                  remote-peers)
                (assoc remote-peers id (new-remote-peer-from-hello hello)))))]
    (send (:remote-peers-agent peer) update-remote-peers hello)))
