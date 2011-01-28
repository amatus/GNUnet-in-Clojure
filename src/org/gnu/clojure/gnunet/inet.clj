(ns org.gnu.clojure.gnunet.inet
  (:use (org.gnu.clojure.gnunet message parser transport)
    clojure.contrib.monads)
  (:import (java.net InetAddress InetSocketAddress NetworkInterface)
    java.util.Date))

(defn encode-address
  [inet-socket-address]
  (vec (concat
         (.getAddress (.getAddress inet-socket-address))
         (encode-int16 (.getPort inet-socket-address)))))

(def parse-address
  (match-one
    (domonad parser-m [addr (items 16)
                       port  parse-uint16]
      (InetSocketAddress. (InetAddress/getByAddress (byte-array addr)) port))
    (domonad parser-m [addr (items 4)
                       port  parse-uint16]
      (InetSocketAddress. (InetAddress/getByAddress (byte-array addr)) port))))

(defn is-unicast-address
  [address]
  (and
    (not (.isAnyLocalAddress address))
    (not (.isMulticastAddress address))))

(defn get-local-addresses
  []
  (for [interface (enumeration-seq (NetworkInterface/getNetworkInterfaces))
        address (enumeration-seq (.getInetAddresses interface))]
    address))

(defn configure-inet-addresses!
  "Adds new addresses for the transport to peer's transports-agent and
   removes expired addresses." 
  [peer transport reachable-addresses port]
  (send (:transport-addresses-agent peer)
    (fn [addresses]
      (merge-transport-addresses {}
        (expire-transport-addresses (Date.)
          (concat (list-transport-addresses addresses)
            (for [address reachable-addresses]
              {:transport transport
               :encoded-address (encode-address
                                  (InetSocketAddress. address port))
               :expiration (hello-address-expiration)})))))))
