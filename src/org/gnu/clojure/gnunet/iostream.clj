(ns org.gnu.clojure.gnunet.iostream
  (:import java.net.URL))

(defn reader
  "Converts a java.io.InputStream into a lazy seq of bytes."
  [in]
  (lazy-seq (let [c (.read in)] (when (>= c 0) (cons (byte c) (reader in))))))

(defn read-url
  "Open a URL and return a seq of its data."
  [url]
  (try
    (reader (.openStream (URL. url)))
    (catch Exception e nil)))
