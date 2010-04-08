(ns org.gnu.clojure.gnunet.peer
  (:use (org.gnu.clojure.gnunet identity)))

(defstruct remote-peer
  :public-key
  :id)

(def peer (apply create-struct (concat
  (keys (struct-map remote-peer))
  (list
    :private-key))))

(defstruct peer-options
  :keypair)

(defn new-peer [options]
  (struct-map peer
    :public-key (.getPublic (:keypair options))
    :private-key (.getPrivate (:keypair options))
    :id (generate-id (:keypair options))))
