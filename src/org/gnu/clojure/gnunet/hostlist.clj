(ns org.gnu.clojure.gnunet.hostlist
  (:use (org.gnu.clojure.gnunet parser message hello iostream)))

(defn download-hostlist
  "Calls the hello-processor on all parsed hello messages at the given URL."
  [url hello-processor]
  (doseq [msg (first ((none-or-more parse-message) (read-url url)))
        :while (== (:message-type msg) message-type-hello)]
    (try
      (hello-processor (first (parse-hello (:bytes msg))))
      (catch Exception e nil))))
