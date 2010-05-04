(ns org.gnu.clojure.gnunet.hostlist
  (:use (org.gnu.clojure.gnunet parser message hello iostream)))

(defn download-hostlist
  "Calls the hello-processor on all parsed hello messages at the given URL."
  [hello-processor url]
  (doseq [[_ msg] (first ((none-or-more (parse-message-types
                                          {message-type-hello parse-hello}))
                           (read-url url)))]
    (hello-processor msg)))
