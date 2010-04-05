(ns org.gnu.clojure.gnunet.peer)

(defstruct peer
  :options)

(defstruct peer-options
  :id)

(defn new-peer [options]
  (struct-map peer
    :options (ref options)))
