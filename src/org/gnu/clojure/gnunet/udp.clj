(ns org.gnu.clojure.gnunet.udp
  (:use (org.gnu.clojure.gnunet inet parser message peer transport)
    clojure.contrib.monads)
  (:import (java.util Date Calendar)
    (java.net InetSocketAddress DatagramPacket)
    (java.nio.channels DatagramChannel SelectionKey)
    java.nio.ByteBuffer))

(def max-udp-packet-length 65536)

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

(defn admit-message-udp!
  [peer datagram-channel]
  (let [byte-buffer (doto (ByteBuffer/allocate max-udp-packet-length) (.clear))
        source-address (.receive datagram-channel byte-buffer)]
    (.flip byte-buffer)
    (let [string-builder (StringBuilder. "Received packet of length ")]
      (.append string-builder (.limit byte-buffer))
      (.append string-builder " from ")
      (.append string-builder source-address)
      (.append string-builder "\n")
      (.write *out* (.toString string-builder)))
  ))

(defn register-datagram-channel!
  [peer port]
  (let [datagram-channel (DatagramChannel/open)
        socket (.socket datagram-channel)]
    (.configureBlocking datagram-channel false)
    (.bind socket (InetSocketAddress. port))
    (let [selection-key (.register datagram-channel
                          (:selector peer)
                          SelectionKey/OP_READ
                          (partial admit-message-udp! peer datagram-channel))]
      (send (:transports-agent peer)
        (fn [transports]
          (assoc transports "udp"
            {:connect! connect-udp!
             :emit-message! emit-message-udp!
             :socket socket
             :selection-key selection-key}))))))

(defn activate-udp!
  [peer port]
  (dosync (alter (:selector-continuations-ref peer)
            conj (partial register-datagram-channel! peer port)))
  (.wakeup (:selector peer)))
