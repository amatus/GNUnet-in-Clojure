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

(defn list-transports
  "Generate a list of transport descriptions."
  [transport-map]
  (for [transport transport-map
        address (val transport)]
    (conj
      {:name (key transport) :encoded-address (key address)}
      (val address))))

(defn merge-addresses
  "Merge two address-info maps."
  [a b]
  (let [expiration (my-max (:expiration a) (:expiration b))
        latency (my-min (:latency a) (:latency b))]
    (if latency
      {:expiration expiration :latency latency}
      {:expiration expiration})))

(defn merge-transports
  "Merge a list of transport descriptions into a transports-agent map. The input
   list is generated from parse-hello or list-transports. The input map is
   described in peer.clj."
  [transport-map transport-list]
  (reduce (fn [transport-map transport]
            (if-let [addresses (transport-map (:name transport))]
              (if-let [address (addresses (:encoded-address transport))]
                (assoc transport-map (:name transport)
                  (assoc addresses (:encoded-address transport)
                    (merge-addresses address transport)))
                (assoc transport-map (:name transport)
                  (assoc addresses (:encoded-address transport)
                    (dissoc transport :name :encoded-address))))
              (assoc transport-map (:name transport)
                {(:encoded-address transport)
                 (dissoc transport :name :encoded-address)})))
    transport-map
    transport-list))

(defn expire-transports
  [min-expiration transport-list]
  (filter #(>= 0 (compare min-expiration (:expiration %))) transport-list))

(defn new-remote-peer-from-hello
  [hello]
  (struct-map remote-peer
    :public-key (:public-key hello)
    :id (generate-id (:public-key hello))
    :transports-agent (agent (merge-transports {} (:transports hello)))))

;; Event - Peer receives a HELLO message
(defn admit-hello!
  "Updates the remote-peers map with new information contained in a hello and
   expires old addresses."
  [peer hello]
  (letfn [(update-transports
            [transports new-transports]
            (merge-transports {}
              (expire-transports (Date.) (concat (list-transports transports)
                                           new-transports))))
          (update-remote-peers
            [remote-peers hello]
            (let [id (vec (generate-id (:public-key hello)))
                  remote-peer (remote-peers id)]
              (if remote-peer
                (do
                  (send
                    (:transports-agent remote-peer)
                    update-transports
                    (:transports hello))
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
  [remote-peer]
  (let [transports (deref (:transports-agent remote-peer))
        current-transports (expire-transports (Date.) (list-transports
                                                          transports))
        usable-transports (filter #(contains? my-transports (key %))
                            current-transports)
        best (first usable-transports)]
  [(my-transports (key best)) (val best)]))

(defn send-message!
  "Sends message to remote-peer."
  [remote-peer message]
  (let [[transport-send! addresses] (best-transport remote-peer)]
    (transport-send! remote-peer addresses message)))

(defn connect-to-peer!
  [remote-peer]
  )
