(ns org.gnu.clojure.gnunet.topology_events)

(defn notify-new-remote-peer!
  [peer remote-peer]
  (let [callbacks (:new-peer-callbacks (deref (:topology-agent peer)))]
    (doseq [callback! callbacks]
      (callback! peer remote-peer))))

