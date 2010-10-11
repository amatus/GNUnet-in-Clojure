(ns org.gnu.clojure.gnunet.transport
  (:use (org.gnu.clojure.gnunet parser message hello peer util crypto)
    clojure.contrib.monads)
  (:import (java.util Date Calendar)))

(defn hello-address-expiration
  []
  (.getTime (doto (Calendar/getInstance) (.add Calendar/HOUR_OF_DAY 12))))

(def message-type-ping 32)
(def message-type-pong 33)

(defn encode-ping
  [ping]
  (concat
    (encode-int32 (:challenge ping))
    (encode-int (:peer-id ping))
    (if-let [transport (:transport ping)]
      (concat
        (encode-utf8 (:transport ping))
        (:encoded-address ping)))))

(def parse-ping
  (domonad parser-m [challenge parse-uint32
                     peer-id (parse-uint id-size)
                     transport (optional parse-utf8)
                     encoded-address (none-or-more item)]
    {:challenge challenge
     :peer-id peer-id
     :transport transport
     :encoded-address encoded-address}))

(defn encode-pong
  [pong]
  (let [transport (encode-utf8 (:transport pong))
        address-length (+ (count transport) (count (:encoded-address pong)))]
    (concat
      (encode-int32 (:challenge pong))
      (:signature pong)
      (encode-int32 (:signature-size pong))
      (encode-int32 (:signature-purpose pong))
      (encode-date (:expiration pong))
      (:peer-id pong)
      (encode-int32 address-length)
      transport
      (:encoded-address pong))))

(def signature-purpose-transport-pong-own 1)
(def signature-purpose-transport-pong-using 2)
(def pong-signature-offset (+ 4 signature-size))

(def parse-pong
  (domonad parser-m [challenge parse-int32
                     signature (items signature-size)
                     signature-size parse-uint32
                     signature-purpose parse-uint32
                     expiration parse-date
                     peer-id (items id-size)
                     address-length parse-uint32
                     transport parse-utf8
                     :when (>= address-length (count (encode-utf8 transport))) 
                     encoded-address (items
                                       (- address-length
                                         (count (encode-utf8 transport))))
                     :when (= signature-size
                             (+ 4 4 8 id-size 4 address-length))
                     residue (none-or-more item)
                     :when (= 0 (count residue))]
    {:challenge challenge
     :signature signature
     :signature-size signature-size
     :signature-purpose signature-purpose
     :expiration expiration
     :peer-id peer-id
     :transport transport
     :encoded-address encoded-address}))

(defn list-transport-addresses
  "Generate a list of transport descriptions."
  [addresses-map]
  (for [transport addresses-map
        address (val transport)]
    (conj
      {:transport (key transport) :encoded-address (key address)}
      (val address))))

(defn merge-address-info
  "Merge two address-info maps."
  [a b]
  (conj a b {:expiration (my-max (:expiration a) (:expiration b))}))

(defn merge-transport-addresses
  "Merge a list of transport descriptions into a transports-agent map. The input
   list is generated from parse-hello or list-transports. The input map is
   described in peer.clj."
  [address-map address-list]
  (reduce (fn [address-map new-address]
            (if-let [transport (address-map (:transport new-address))]
              (if-let [address-info (transport (:encoded-address new-address))]
                (assoc address-map (:transport new-address)
                  (assoc transport (:encoded-address new-address)
                    (merge-address-info address-info
                      (dissoc new-address :transport :encoded-address))))
                (assoc address-map (:transport new-address)
                  (assoc transport (:encoded-address new-address)
                    (dissoc new-address :transport :encoded-address))))
              (assoc address-map (:transport new-address)
                {(:encoded-address new-address)
                 (dissoc new-address :transport :encoded-address)})))
    address-map
    address-list))

(defn expire-transport-addresses
  [min-expiration addresses-list]
  (filter #(>= 0 (compare min-expiration (:expiration %))) addresses-list))

(defn new-remote-peer-from-hello
  [peer-id hello]
  (struct-map remote-peer
    :public-key (:public-key hello)
    :id peer-id
    :transport-addresses-agent (agent (merge-transport-addresses {}
                                        (:transport-addresses hello)))
    :connection-agent (agent {})))

(defn hello-for-peer-message
  [peer]
  {:message-type message-type-hello
   :bytes (encode-hello
            {:public-key (:public-key peer)
             :transport-addresses (list-transport-addresses
                                    (deref
                                      (:transport-addresses-agent peer)))})})

(defn ping-message
  [remote-peer address challenge]
  {:message-type message-type-ping
   :bytes (encode-ping {:challenge challenge
                        :peer-id (:id remote-peer)
                        :transport (:transport address)
                        :encoded-address (:encoded-address address)})})

(defn- update-transport-addresses
  [addresses new-addresses]
  (merge-transport-addresses {}
    (expire-transport-addresses (Date.)
      (concat (list-transport-addresses addresses) new-addresses))))

(defn- update-remote-peers
  [remote-peers peer-id hello]
  (let [id (vec peer-id)
        remote-peer (remote-peers id)]
    (if remote-peer
      (do
        (send (:transport-addresses-agent remote-peer)
          update-transport-addresses
          (:transport-addresses hello))
        remote-peers)
      (assoc remote-peers id (new-remote-peer-from-hello peer-id hello)))))

(defn verify-transport-address
  [peer remote-peer address]
  (if (or (contains? address :latency)
        (contains? address :send-time))
    address
    (if-let [transport ((deref (:transports-agent peer))
                         (:transport address))]
      (let [challenge (.nextInt (:random peer))]
        ((:emit-messages! transport) transport (:encoded-address address)
          [(hello-for-peer-message peer)
           (ping-message remote-peer address challenge)])
        (conj address
          {:send-time (Date.)    ;; TODO: Now is not the actual send time.
           :challenge challenge}))
      address)))

(defn verify-transport-addresses
  [addresses peer remote-peer]
  (merge-transport-addresses {}
    (map (partial verify-transport-address peer remote-peer)
      (list-transport-addresses addresses))))

(defn verify-remote-peers
  [remote-peers peer]
  (doseq [[_ remote-peer] remote-peers]
    (send (:transport-addresses-agent remote-peer)
      verify-transport-addresses peer remote-peer))
  remote-peers)

(defn admit-hello!
  "Updates peer:remote-peers-agent with new information contained in hello."
  [peer hello]
  (let [peer-id (generate-id (:public-key hello))]
    (if (not (= peer-id (:id peer)))
      (let [remote-peers-agent (:remote-peers-agent peer)]
        (send remote-peers-agent update-remote-peers peer-id hello)
        (send remote-peers-agent verify-remote-peers peer)))))

(defn handle-hello!
  [peer message]
  (when-let [hello (first (parse-hello (:bytes message)))]
    (admit-hello! peer hello)))

(defn best-transport
  [peer remote-peer]
  (let [addresses (deref (:transport-addressess-agent remote-peer))
        current-addresses (expire-transport-addresses (Date.)
                            (list-transport-addresses addresses))
        transports (deref (:transports-agent peer))
        usable-addresses (filter #(contains? transports (:transport %))
                           current-addresses)
        sorted-addresses (sort-by #(if-let [latency (:latency %)]
                                     latency
                                     Integer/MAX_VALUE)
                           usable-addresses)
        best (first sorted-addresses)]
  {:address best
   :transport (transports (:transport best))}))

(defn connect-to-peer!
  [peer remote-peer]
  (send (:connection-agent remote-peer)
    (fn [connection]
      (if (contains? connection :transport)
        (let [{transport :transport address :address} (best-transport peer
                                                        remote-peer)]
          (conj {:transport transport :address address}
            ((:connect! transport) peer remote-peer address)))))))

(defn handle-ping!
  [peer sender-id source-address message]
  
  )

(defn check-pending-validation
  [addresses remote-peer pong encoded-pong]
  (if-let [transport (addresses (:transport pong))]
    (if-let [address (transport (:encoded-address pong))]
      (cond
        (not (= (:challenge address) (:challenge pong)))
          addresses
        (= signature-purpose-transport-pong-own (:signature-purpose pong))
          (if (rsa-verify (:public-key remote-peer)
                (drop pong-signature-offset encoded-pong)
                (:signature pong))
            (assoc addresses (:transport pong)
              (assoc transport (:encoded-address pong)
                {:expiration (hello-address-expiration)
                 :latency (- (.getTime (Date.))
                            (.getTime (:send-time address)))}))
            addresses)
        (= signature-purpose-transport-pong-using (:signature-purpose pong))
          ;; TODO - fill in this case
          addresses
        :else addresses)
      addresses)
    addresses))

(defn handle-pong!
  [peer sender-id source-address message]
  (when-let [pong (first (parse-pong (:bytes message)))]
    (if (>= 0 (.compareTo (Date.) (:expiration pong)))
      (when-let [remote-peer ((deref (:remote-peers-agent peer))
                               (:peer-id pong))]
        (send (:transport-addresses-agent remote-peer) check-pending-validation
          remote-peer pong (:bytes message))))))

(defn admit-message!
  [peer sender-id source-address message]
  (let [string-builder (StringBuilder. "Received message type ")]
      (.append string-builder (:message-type message))
      (.append string-builder " from ")
      (.append string-builder source-address)
      (.append string-builder " id ")
      (.append string-builder sender-id)
      (.append string-builder "\n")
      (.write *out* (.toString string-builder)))
  (condp = (:message-type message)
    message-type-hello (handle-hello! peer message)
    message-type-ping (handle-ping! peer sender-id source-address message)
    message-type-pong (handle-pong! peer sender-id source-address message)
    nil))
