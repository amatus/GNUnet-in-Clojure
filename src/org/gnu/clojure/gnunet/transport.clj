(ns org.gnu.clojure.gnunet.transport
  (:use (org.gnu.clojure.gnunet parser message hello peer)
    clojure.contrib.monads)
  (:import java.util.Date))

(defn my-min
  "Return the non-nil minimum in a collection of comparable values."
  [& coll]
  (first (sort (filter #(not (nil? %)) coll))))

(defn my-max
  "Return the non-nil maximum in a collection of comparable values."
  [& coll]
  (last (sort (filter #(not (nil? %)) coll))))

(defn list-transport-addresses
  "Generate a list of transport descriptions."
  [addresses-map]
  (for [transport addresses-map
        address (val transport)]
    (conj
      {:transport (key transport) :encoded-address (key address)}
      (val address))))

(defn merge-address-info
  "Merge two address-info maps."
  [a b]
  (let [expiration (my-max (:expiration a) (:expiration b))
        latency (my-min (:latency a) (:latency b))]
    (if latency
      {:expiration expiration :latency latency}
      {:expiration expiration})))

(defn merge-transport-addresses
  "Merge a list of transport descriptions into a transports-agent map. The input
   list is generated from parse-hello or list-transports. The input map is
   described in peer.clj."
  [address-map address-list]
  (reduce (fn [address-map new-address]
            (if-let [transport (address-map (:transport new-address))]
              (if-let [address-info (transport (:encoded-address new-address))]
                (assoc address-map (:transport new-address)
                  (assoc transport (:encoded-address new-address)
                    (merge-address-info address-info new-address)))
                (assoc address-map (:transport new-address)
                  (assoc transport (:encoded-address new-address)
                    (dissoc new-address :transport :encoded-address))))
              (assoc address-map (:transport new-address)
                {(:encoded-address new-address)
                 (dissoc new-address :transport :encoded-address)})))
    address-map
    address-list))

(defn expire-transport-addresses
  [min-expiration addresses-list]
  (filter #(>= 0 (compare min-expiration (:expiration %))) addresses-list))

(defn new-remote-peer-from-hello
  [hello]
  (struct-map remote-peer
    :public-key (:public-key hello)
    :id (generate-id (:public-key hello))
    :transport-addresses-agent (agent (merge-transport-addresses {}
                                        (:transport-addresses hello)))
    :connection-agent (agent {})))

;; Event - Peer receives a HELLO message
(defn admit-hello!
  "Updates the remote-peers map with new information contained in a hello and
   expires old addresses."
  [peer hello]
  (letfn [(update-transport-addresses
            [addresses new-addresses]
            (merge-transport-addresses {}
              (expire-transport-addresses (Date.)
                (concat (list-transport-addresses addresses) new-addresses))))
          (update-remote-peers
            [remote-peers hello]
            (let [id (vec (generate-id (:public-key hello)))
                  remote-peer (remote-peers id)]
              (if remote-peer
                (do
                  (send
                    (:transport-addresses-agent remote-peer)
                    update-transport-addresses
                    (:transport-addresses hello))
                  remote-peers)
                (assoc remote-peers id (new-remote-peer-from-hello hello)))))]
    (send (:remote-peers-agent peer) update-remote-peers hello)))

(def message-type-ping 32)

(defn encode-ping
  [ping]
  (concat
    (encode-int32 (:challenge ping))
    (encode-int (:peer-id ping))))

(def parse-ping
  (domonad parser-m [challenge parse-uint32
                     peer-id (parse-uint id-size)]
    {:challenge challenge :peer-id peer-id}))

(defn best-transport
  [peer remote-peer]
  (let [addresses (deref (:transport-addressess-agent remote-peer))
        current-addresses (expire-transport-addresses (Date.)
                            (list-transport-addresses addresses))
        transports (deref (:transports-agent peer))
        usable-addresses (filter #(contains? transports (:transport %))
                           current-addresses)
        sorted-addresses (sort-by #(if-let [latency (:latency %)] latency 0)
                           usable-addresses)
        best (first sorted-addresses)]
  {:address best
   :transport (transports (:transport best))}))

(defn connect-to-peer!
  [peer remote-peer]
  (send (:connection-agent remote-peer)
    (fn [connection]
      (if (contains? connection :transport)
        (let [{transport :transport address :address} (best-transport peer
                                                        remote-peer)]
          (do
            ((:connect! transport) peer remote-peer address)
            {:transport transport
             :transport-name (:transport address)}))))))
