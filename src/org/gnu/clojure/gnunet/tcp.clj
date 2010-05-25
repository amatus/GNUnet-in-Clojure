(ns org.gnu.clojure.gnunet.tcp
  (:use (org.gnu.clojure.gnunet parser message identity crypto)
    clojure.contrib.monads)
  (:import (java.net InetAddress InetSocketAddress)))

(def message-type-tcp-welcome 60)

(defn encode-welcome
  [my-id]
  my-id)

(def parse-welcome
  (domonad parser-m [my-id (items id-size)] my-id))

(defn encode-address
  [inet-socket-address]
  (concat
    (.getAddress (.getAddress inet-socket-address))
    (encode-int16 (.getPort inet-socket-address))))

(def parse-address
  (match-one
    (domonad parser-m [addr (items 16)
                       port  parse-uint16]
      (InetSocketAddress. (InetAddress/getByAddress (byte-array addr)) port))
    (domonad parser-m [addr (items 4)
                       port  parse-uint16]
      (InetSocketAddress. (InetAddress/getByAddress (byte-array addr)) port))))
