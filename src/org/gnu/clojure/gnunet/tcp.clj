(ns org.gnu.clojure.gnunet.tcp
  (:use (org.gnu.clojure.gnunet identity parser) clojure.contrib.monads))

(def message-type-tcp-welcome 60)

(defn encode-welcome
  [my-id]
  my-id)

(def parse-welcome
  (domonad parser-m [my-id (items id-size)] my-id))
