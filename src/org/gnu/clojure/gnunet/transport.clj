(ns org.gnu.clojure.gnunet.transport
  (:use (org.gnu.clojure.gnunet udp hello))
  (:import java.util.Date))

(def my-transports {"udp" udp-send!})

(defn best-transport
  [transports]
  (let [current-transports (merge-transports (Date.) {} (list-transports
                                                          transports))
        usable-transports (filter #(contains? my-transports (key %))
                            current-transports)
        best (first usable-transports)]
  [(my-transports (key best)) (val best)]))

(defn send-message!
  "Sends message to remote-peer."
  [remote-peer message]
  (let [[transport-send! addresses] (best-transport
                                      (deref (:transports-agent remote-peer)))]
    (transport-send! remote-peer addresses message)))
