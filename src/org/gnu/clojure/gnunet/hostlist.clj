(ns org.gnu.clojure.gnunet.hostlist
  (:use (org.gnu.clojure.gnunet parser message hello iostream peer identity))
  (:import (java.util Date TimerTask)))

(defn download-hostlist!
  "Calls hello-processor! on all parsed hello messages at the given URL."
  [hello-processor! url]
  (doseq [{hello :message} (first
                             ((none-or-more (parse-message-types
                                              {message-type-hello parse-hello}))
                               (read-url url)))]
    (hello-processor! hello)))

;; Event - Peer receives a HELLO message
(defn admit-hello!
  "Updates the remote-peers map with new information contained in a hello."
  [peer hello]
  (letfn [(update-transports
            [transports new-transports]
            (merge-transports (Date.)
              transports
              (list-transports new-transports)))
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

(defn create-hostlist-timer-task
  "Creates a TimerTask that when run fetches the hostlist at url and updates
   peer."
  [peer url]
  (proxy [java.util.TimerTask] []
    (run [] (download-hostlist! (partial admit-hello! peer) url))))
