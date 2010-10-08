(ns org.gnu.clojure.gnunet.hostlist
  (:use (org.gnu.clojure.gnunet parser message hello iostream peer transport))
  (:import java.util.TimerTask))

(def parse-hostlist
  (none-or-more (parse-message-types {message-type-hello parse-hello})))

(defn download-hostlist!
  "Calls hello-processor! on all parsed hello messages at the given URL."
  [hello-processor! url]
  (doseq [{hello :message} (first (parse-hostlist (read-url url)))]
    (hello-processor! hello)))

(defn create-hostlist-timer-task
  "Creates a TimerTask that when run fetches the hostlist at url and updates
   peer."
  [peer url]
  (proxy [java.util.TimerTask] []
    (run [] (download-hostlist! (partial admit-hello! peer) url))))
