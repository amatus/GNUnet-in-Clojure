(ns org.gnu.clojure.gnunet.inet
  (:use (org.gnu.clojure.gnunet parser message)
    clojure.contrib.monads)
  (:import (java.net InetAddress InetSocketAddress)))

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
