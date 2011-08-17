(ns org.gnu.clojure.gnunet.topology
  (:use (org.gnu.clojure.gnunet peer transport)))

(defn verify-transport-address!
  [peer remote-peer address]
  (second
    ((domonad exception-m
       [address (fetch-state)
        :when-not (or (contains? address :latency)
                     (contains? address :send-time))
        :when-let [transport ((deref (:transports-agent peer))
                               (:transport address))]
        :let [challenge (.nextInt (:random peer))]
        _ (set-state
            (conj address
              {:send-time (Date.)    ;; TODO: Now is not the actual send time.
               :challenge challenge}))]
       ((:emit-messages! transport) transport remote-peer
         (:encoded-address address) nil
         [(hello-for-peer-message peer)
          (ping-message remote-peer address challenge)])) address)))

(defn verify-transport-addresses!
  [addresses peer remote-peer]
  (merge-transport-addresses {}
    (map (partial verify-transport-address! peer remote-peer)
      (list-transport-addresses addresses))))

(defn verify-remote-peers!
  [remote-peers peer]
  (doseq [[_ remote-peer] remote-peers]
    (send (:transport-addresses-agent remote-peer)
      verify-transport-addresses! peer remote-peer))
  remote-peers)

(defn activate-topology!
  [peer]
  )
