(ns org.gnu.clojure.gnunet.udp
  (:use (org.gnu.clojure.gnunet inet parser message peer transport)
    clojure.contrib.monads)
  (:import (java.util Date Calendar) java.net.InetSocketAddress))

(defn configure-udp-addresses!
  "Adds new addresses for the udp transport to peer's transports-agent expiring
   in 30 days and removes expired addresses." 
  [peer addresses port]
  (send (:transports-agent peer)
    (fn [transports]
      (merge-transports {}
        (expire-transports (Date.)
          (concat (list-transports transports)
            (for [address addresses]
              {:name "udp"
               :encoded-address (encode-address (InetSocketAddress. address
                                                  port))
               :expiration (.getTime (doto (Calendar/getInstance)
                                       (.add Calendar/DAY_OF_MONTH 30)))})))))))

(defn pick-address
  [addresses]
  (let [parsed-addresses (map #(first (parse-address (key %))) addresses)
        usable-addresses (filter #(and % (is-unicast-address (.getAddress %)))
                           parsed-addresses)]
  (first usable-addresses)))

(defn udp-send!
  [remote-peer addresses encoded-message]
  (let [address (pick-address addresses)]
    ))

(def parse-udp
  (domonad parser-m [peer-id (parse-uint id-size)
                     messages (none-or-more parse-message)]
    {:peer-id peer-id :messages messages}))
