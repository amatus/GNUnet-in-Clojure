(ns org.gnu.clojure.gnunet.transport
  (:use (org.gnu.clojure.gnunet core crypto exception message metrics parser
                                peer topology_events util)
    clojure.contrib.monads)
  (:import (java.util Date Calendar)))

(defn hello-address-expiration
  []
  (.getTime (doto (Calendar/getInstance) (.add Calendar/HOUR_OF_DAY 12))))

(defn pong-expiration
  []
  (.getTime (doto (Calendar/getInstance) (.add Calendar/HOUR_OF_DAY 1))))

(defn idle-connection-timeout
  []
  (.getTime (doto (Calendar/getInstance) (.add Calendar/MINUTE 5))))

(def message-type-hello 16)
(def message-type-transport-ping 32)
(def message-type-transport-pong 33)
(def message-type-transport-connect 35)
(def message-type-transport-disconnect 36)
(def message-type-transport-keepalive 39)

(def signature-purpose-pong-own 1)

(defn encode-transport-address
  [address]
  (concat
    (encode-utf8 (:transport address))
    (encode-int16 (count (:encoded-address address)))
    (encode-date (:expiration address))
    (:encoded-address address)))

(def parse-transport-address
  (domonad parser-m [transport parse-utf8
                     address-length parse-uint16
                     expiration parse-date
                     encoded-address (items address-length)]
    {:transport transport
     :expiration expiration
     :encoded-address encoded-address}))

(defn encode-hello
  "Encode a hello message."
  [hello]
  (concat
    (encode-int32 0)
    (encode-rsa-public-key (:public-key hello))
    (mapcat encode-transport-address (:transport-addresses hello))))

(def parse-hello
  (domonad parser-m [padding parse-uint32
                     :when (== padding 0)
                     public-key parse-rsa-public-key
                     addresses (none-or-more parse-transport-address)]
    {:public-key public-key
     :transport-addresses addresses}))

(defn encode-ping
  [ping]
  (concat
    (encode-int32 (:challenge ping))
    (:peer-id ping)
    (when-let [transport (:transport ping)]
      (concat
        (encode-utf8 transport)
        (:encoded-address ping)))))

(def parse-ping
  (domonad parser-m
    [challenge parse-uint32
     peer-id (items id-size)
     transport (optional parse-utf8)
     encoded-address (none-or-more item)]
    {:challenge challenge
     :peer-id peer-id
     :transport transport
     :encoded-address encoded-address}))

(defn encode-pong-signed-material
  [pong]
  (let [transport (when (:transport pong) (encode-utf8 (:transport pong)))
        address-length (+ (count transport) (count (:encoded-address pong)))]
    (encode-signed (:signature-purpose pong)
      (concat
        (encode-date (:expiration pong))
        (encode-int32 address-length)
        transport
        (:encoded-address pong)))))

(defn encode-pong
  [pong signed-material]
  (concat
    (encode-int32 (:challenge pong))
    (:signature pong)
    signed-material))

(def parse-pong
  (domonad parser-m
    [challenge parse-int32
     signature (items signature-size)
     signed (parse-signed
              (domonad parser-m
                [expiration parse-date
                 address-length parse-uint32
                 transport (none-or-more (satisfy #(not (== 0 %))))
                 zero item
                 :let [transport-length (inc (count transport))]
                 :when (>= address-length transport-length)
                 encoded-address (items (- address-length transport-length))]
                {:expiration expiration
                 :transport (String. (byte-array transport) "UTF-8")
                 :encoded-address encoded-address}))
     :let [signature-purpose (:purpose signed)]
     :when (== signature-purpose signature-purpose-pong-own)
     residue (optional item)
     :when (nil? residue)]
    (conj {:challenge challenge
           :signature signature
           :signature-purpose signature-purpose
           :signed-material (:signed-material signed)}
      (:parsed signed))))

(defn encode-connect
  [connect]
  (concat
    (encode-int32 0)
    (encode-date (:timestamp connect))))

(def parse-connect
  (domonad
    parser-m
    [reserved parse-uint32
     timestamp parse-date]
    {:timestamp timestamp}))

(defn list-transport-addresses
  "Generate a list of transport addresses."
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
  "Merge a list of transport addresses into a transports-agent map. The input
   list is generated from parse-hello or list-transport-addresses. The map is
   described in peer.clj."
  [address-map address-list]
  (reduce
    (fn [address-map new-address]
      (assoc-deep
        address-map
        (dissoc new-address :transport :encoded-address)
        (:transport new-address)
        (:encoded-address new-address)))
    address-map
    address-list))

(defn expire-transport-addresses
  [min-expiration addresses-list]
  (filter #(not (.after min-expiration (:expiration %))) addresses-list))

(defn hello-for-peer-message
  [peer]
  {:message-type message-type-hello
   :bytes (encode-hello
            {:public-key (deref (:public-key-atom peer))
             :transport-addresses (list-transport-addresses
                                    (deref
                                      (:transport-addresses-agent peer)))})})

(defn ping-message
  [remote-peer address challenge]
  {:message-type message-type-transport-ping
   :bytes (encode-ping {:challenge challenge
                        :peer-id (:id remote-peer)
                        :transport (:transport address)
                        :encoded-address (:encoded-address address)})})

(defn update-transport-addresses
  [addresses new-addresses]
  (merge-transport-addresses {}
    (expire-transport-addresses (Date.)
      (concat (list-transport-addresses addresses) new-addresses))))

(defn update-remote-peers!
  [remote-peers peer peer-id hello]
  (if-let [remote-peer (remote-peers peer-id)]
    (do
      (if (:public-key hello)
        (swap! (:public-key-atom remote-peer)
          #(if (nil? %) (:public-key hello))))
      (send (:transport-addresses-agent remote-peer)
        update-transport-addresses
        (:transport-addresses hello))
      remote-peers)
    (let
      [remote-peer
       (struct-map
         remote-peer-struct
         :public-key-atom (atom (:public-key hello))
         :id peer-id
         :transport-addresses-agent (agent
                                      (merge-transport-addresses
                                        {} (:transport-addresses hello)))
         :state-agent (agent {:is-connected false}))]
      (notify-new-remote-peer! peer remote-peer)
      (assoc remote-peers peer-id remote-peer))))

(defn admit-hello!
  "Updates peer:remote-peers-agent with new information contained in hello."
  [peer hello]
  (let [peer-id (generate-id (:public-key hello))]
    (when-not (= peer-id (:id peer))
      (send (:remote-peers-agent peer)
            update-remote-peers! peer peer-id hello))))

(defn handle-hello!
  [peer message]
  (when-let [hello (first (parse-hello (:bytes message)))]
    (admit-hello! peer hello)))

(defn send-pong-own!
  [peer remote-peer ping]
  (.execute (:cpu-bound-executor peer)
    (fn []
      (domonad maybe-m
        [transport-addresses ((deref (:transport-addresses-agent peer))
                               (:transport ping))
         ;; XXX: Here we're looking for an exact match, gnunet allows transport
         ;; plugins to do inexact matches.
         :when (contains? transport-addresses (:encoded-address ping))
         pong {:challenge (:challenge ping)
               :signature-purpose signature-purpose-pong-own
               :expiration (pong-expiration)
               :transport (:transport ping)
               :encoded-address (:encoded-address ping)}
         signed-material (encode-pong-signed-material pong)
         signature (rsa-sign (:private-key peer) signed-material)
         pong (assoc pong :signature signature)
         encoded-pong (encode-pong pong signed-material)
         state (deref (:state-agent remote-peer))]
        (if (:is-connected state)
          (let [transport (:connected-transport state)
                encoded-address (:connected-address state)]
            ((:emit-messages! transport)
               transport remote-peer encoded-address nil
               [{:message-type message-type-transport-pong
                 :bytes encoded-pong}]))
          (doseq [transports (deref (:transport-addresses-agent remote-peer))
                  address (val transports)]
            (when-let [transport ((deref (:transports-agent peer))
                                   (key transports))]
              ((:emit-messages! transport)
                 transport remote-peer (key address) nil
                [{:message-type message-type-transport-pong
                  :bytes encoded-pong}]))))))))

(defn handle-ping!
  [peer remote-peer message]
  (when-let [ping (first (parse-ping (:bytes message)))]
    (cond
      (not (= (:peer-id ping) (:id peer))) nil
      (:transport ping) (send-pong-own! peer remote-peer ping))))

(defn handle-pong-own!
  [peer remote-peer pong]
  (domonad
    maybe-m
    [transport (:transport pong)
     encoded-address (:encoded-address pong)
     transport-addresses (deref (:transport-addresses-agent remote-peer))
     addresses (transport-addresses transport)
     address (addresses encoded-address)
     :when (= (:challenge address) (:challenge pong))]
    (.execute
      (:cpu-bound-executor peer)
      (fn []
        (domonad
          maybe-m
          [public-key (deref (:public-key-atom remote-peer))
           :when (rsa-verify public-key (:signed-material pong)
                             (:signature pong))]
          (send-do-exception-m!
            (:transport-addresses-agent remote-peer)
            [_ (with-state-field
                 transport
                 (set-val
                   encoded-address
                   {:expiration (hello-address-expiration)
                    :latency (- (.getTime (Date.))
                                (.getTime (:send-time address)))}))]
            (notify-new-valid-address! peer remote-peer transport
                                       encoded-address)))))))

(defn handle-pong!
  [peer remote-peer message]
  (domonad maybe-m
    [pong (first (parse-pong (:bytes message)))
     :when-not (.after (Date.) (:expiration pong))]
    (condp == (:signature-purpose pong)
      signature-purpose-pong-own (handle-pong-own! peer remote-peer pong)
      nil)))

(defn emit-callback!
  [peer transport remote-peer encoded-address result]
  (when result
    (let [addresses ((deref (:transport-addresses-agent remote-peer))
                      (:name transport))
          address (addresses encoded-address)]
      (if (contains? address :latency)
        (send (:state-agent remote-peer)
          (fn [state]
            (conj state {:is-connected true
                         :connected-transport transport
                         :connected-address encoded-address})))))))

(defn admit-message!
  [peer sender-id message]
  ;; (.write *out* (str "Received " message "\n"))
  (send (:remote-peers-agent peer)
    (fn [remote-peers]
      (let [remote-peers (update-remote-peers! remote-peers peer sender-id {})
            remote-peer (remote-peers sender-id)]
        (condp = (:message-type message)
          message-type-hello (handle-hello! peer message)
          message-type-transport-ping (handle-ping! peer remote-peer message)
          message-type-transport-pong (handle-pong! peer remote-peer message)
          (handle-receive! peer remote-peer message))
        remote-peers))))
