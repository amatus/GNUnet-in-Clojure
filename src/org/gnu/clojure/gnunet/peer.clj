(ns org.gnu.clojure.gnunet.peer
  (:use (org.gnu.clojure.gnunet identity)))

(defstruct remote-peer
  :id)

(def peer (apply create-struct (concat
  (keys (struct-map remote-peer))
  (list :keypair))))

(defstruct peer-options
  :keypair)

(defn new-peer [options]
  (struct-map peer
    :keypair (:keypair options)
    :id (generate-id (:keypair options))))
