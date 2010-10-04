(ns org.gnu.clojure.gnunet.udp
  (:use (org.gnu.clojure.gnunet inet parser message peer transport)
    clojure.contrib.monads)
  (:import (java.util Date Calendar)
    java.net.InetSocketAddress
    (java.nio.channels DatagramChannel SelectionKey)))

(defn configure-udp-addresses!
  "Adds new addresses for the udp transport to peer's transports-agent expiring
   in 12 hours and removes expired addresses." 
  [peer reachable-addresses port]
  (send (:transport-addresses-agent peer)
    (fn [addresses]
      (merge-transport-addresses {}
        (expire-transport-addresses (Date.)
          (concat (list-transport-addresses addresses)
            (for [address reachable-addresses]
              {:transport "udp"
               :encoded-address (encode-address (InetSocketAddress. address
                                                  port))
               :expiration (.getTime (doto (Calendar/getInstance)
                                       (.add Calendar/HOUR_OF_DAY 12)))})))))))

(defn pick-address
  [addresses]
  (let [parsed-addresses (map #(first (parse-address (key %))) addresses)
        usable-addresses (filter #(and % (is-unicast-address (.getAddress %)))
                           parsed-addresses)]
  (first usable-addresses)))

(defn emit-message-udp!
  [remote-peer addresses encoded-message]
  (let [address (pick-address addresses)]
    ))

(def parse-udp
  (domonad parser-m [peer-id (parse-uint id-size)
                     messages (none-or-more parse-message)]
    {:peer-id peer-id :messages messages}))

(defn connect-udp!
  [peer remote-peer address]
  )

(defn activate-udp!
  [peer port]
  (let [datagram-channel (DatagramChannel/open)
        socket (.socket datagram-channel)
        selection-key (do
                        (.configureBlocking datagram-channel false)
                        (.bind socket (InetSocketAddress. port))
                        (.register datagram-channel
                          (:selector peer)
                          SelectionKey/OP_READ
                          nil))]
  (send (:transports-agent peer)
    (fn [transports]
      (assoc transports "udp"
        {:connect! connect-udp!
         :emit-message! emit-message-udp!
         :socket socket
         :selection-key selection-key})))))
