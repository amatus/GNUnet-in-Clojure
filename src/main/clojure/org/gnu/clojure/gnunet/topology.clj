(ns org.gnu.clojure.gnunet.topology
  (:use clojure.contrib.monads
        (org.gnu.clojure.gnunet exception peer transport util))
  (:import java.util.Date))

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

(defn new-peer-callback!
  [peer remote-peer]
  ;; XXX: We need to check some kind of current connection count vs target
  ;; connection count before doing this.
  (send (:transport-addresses-agent remote-peer)
    verify-transport-addresses! peer remote-peer))

(defn new-valid-address-callback!
  [peer remote-peer transport-name encoded-address]
  (let [transport ((deref (:transports-agent peer)) transport-name)]
    ((:emit-messages! transport) transport remote-peer encoded-address nil
       [(connect-message)])))

(defn activate-topology!
  [peer]
  (send
    (:topology-agent peer)
    conj-vals
    #{}
    [:new-peer-callbacks new-peer-callback!
     :new-valid-address-callbacks new-valid-address-callback!]))
