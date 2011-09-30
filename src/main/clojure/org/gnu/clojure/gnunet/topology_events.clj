(ns org.gnu.clojure.gnunet.topology_events
  (:use org.gnu.clojure.gnunet.util))

(defn notify-new-remote-peer!
  [peer remote-peer]
  (do-callbacks! (:new-peer-callbacks (deref (:topology-agent peer)))
                 peer remote-peer))

(defn notify-new-valid-address!
  [peer remote-peer transport encoded-address]
  (do-callbacks! (:new-valid-address-callbacks (deref (:topology-agent peer)))
                 peer remote-peer transport encoded-address))
