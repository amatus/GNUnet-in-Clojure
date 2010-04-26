(ns org.gnu.clojure.gnunet.hello
  (:use (org.gnu.clojure.gnunet message identity crypto)))

(def message-type-hello 16)

(defn encode-transport
  [transport]
  (concat
    (.getBytes (:name transport) "UTF-8")
    (list (byte 0))
    (encode-int32 (count (:bytes transport)))
    (encode-int64 (.getTime (:expiration transport)))
    (:bytes transport)))

(defn decode-transport-and-split
  [a]
  (let [[encoded-name after-encoded-name]
          (split-with (fn [x] (not (== x 0))) a)
        [term after-term] (split-at-or-throw 1 after-encoded-name)
        [address-length after-address-length]
          (decode-uint32-and-split after-term)
        [expiration after-expiration]
          (decode-uint64-and-split after-address-length)
        [encoded-address after-encoded-address]
          (split-at address-length after-expiration)]
    [{:name (java.lang.String. (byte-array encoded-name) "UTF-8")
      :expiration (java.util.Date. expiration)
      :bytes encoded-address}
     after-encoded-address]))

(defn many
  [f a]
  (loop [result (list)
         tail a]
    (try
      (let [[one after-one] (f tail)]
        (recur (cons one result) after-one))
      (catch Exception e [result tail]))))

(defn decode-transports-and-split
  [a]
  (many decode-transport-and-split a))

(defn encode-hello
  "Encode a hello message."
  [hello]
  (concat
    (encode-int32 0)
    (encode-rsa-public-key (:public-key hello))
    (mapcat encode-transport (:transports hello))))

(defn decode-hello-and-split
  "Split a seq into a hello and the rest."
  [a]
  (let [[padding after-padding] (decode-uint32-and-split a)
        [public-key after-public-key] (decode-rsa-public-key-and-split
                                        after-padding)
        [transports after-transports] (decode-transports-and-split
                                        after-public-key)]
    (if (not (== padding 0))
      (throw (java.lang.Exception. "Must be zero.")))
    [{:public-key public-key
      :transports transports}
     after-transports]))
