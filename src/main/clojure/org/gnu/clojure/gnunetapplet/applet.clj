(ns org.gnu.clojure.gnunetapplet.applet
  (:use clojure.contrib.json
    [clojure.main :only (repl)]
    (org.gnu.clojure.gnunet crypto hostlist inet peer tcp transport)
    org.gnu.clojure.gnunetapplet.base64)
  (:import
    clojure.lang.LineNumberingPushbackReader
    (java.io InputStreamReader OutputStreamWriter
      PipedInputStream PipedOutputStream PrintWriter)
    java.security.SecureRandom
    java.security.spec.InvalidKeySpecException
    java.util.concurrent.Executors
    netscape.javascript.JSObject)
  (:gen-class
   :extends java.applet.Applet
   :state state
   :init ctor
   :main false
   :set-context-classloader true
   :methods [[ver [] String]
             [repl [netscape.javascript.JSObject
                    netscape.javascript.JSObject]
              java.io.PipedOutputStream]
             [write [java.io.PipedOutputStream String] Void]
             [generateKey [netscape.javascript.JSObject] Void]
             [startPeer [String netscape.javascript.JSObject] Void]
             [configureTCP [clojure.lang.APersistentMap int] Void]
             [watchPeers [clojure.lang.APersistentMap
                          netscape.javascript.JSObject] Void]
             [fetchHostlist [clojure.lang.APersistentMap String] Void]]))

(def applet-ns *ns*)

(defn -ctor
  "The job of this constructor is to initialize state. The rest of the
   initalization happens in the Applet init method."
  []
  ;; Instead of (set! *warn-on-reflection* true)
  ;;(push-thread-bindings {#'*warn-on-reflection* true})
  [[] (ref {})])

(defn jscall-wait
  [applet f & args]
  (try
    (.call (JSObject/getWindow applet) f (object-array args))
    (catch Exception e
      (.printStackTrace e (System/err)))))
  
(defn jscall
  "Call a javascript function named f with args."
  [applet f & args]
  (.execute (:js-executor @(.state applet))
    #(apply jscall-wait applet f args))) 

(defn jsobject-call
  "Call a javascript function f with args."
  [applet ^JSObject f & args]
  (.execute (:js-executor @(.state applet))
    (fn []
      (try
        (.call f "call" (object-array (cons applet args)))
        (catch Exception e
          (.printStackTrace e (System/err)))))))

(defn -init
  "Initialize applet."
  [applet]
  (let [js-executor (Executors/newSingleThreadExecutor)
        priv-executor (Executors/newSingleThreadExecutor)
        random (SecureRandom.)]
    (dosync
      (alter (.state applet) conj
        {:js-executor js-executor
         :priv-executor priv-executor
         :random random}))
    ;; Prime the priv-executor
    (.execute priv-executor
      #(jscall applet "gnunetInit"))))

(defn -ver
  "Returns the version of this applet. Mainly for debugging."
  [applet]
  "0.22")

(defn my-repl
  [applet stdin stdout stderr]
  (.setContextClassLoader (Thread/currentThread)
    (.getClassLoader (.getClass applet)))
  (declare ^:dynamic *applet*)
  (with-bindings {#'*in* stdin
                  #'*out* stdout
                  #'*err* stderr
                  #'*ns* applet-ns
                  #'*applet* applet}
    (repl)))

(defn -repl
  "Creates a REPL thread which calls the javascript functions out and err.
   Returns a PipedOutputStream for input to the REPL."
  [applet out err]
  (let [input (PipedOutputStream.)]
    (.execute (:priv-executor @(.state applet))
      (fn []
        (let [stdin (LineNumberingPushbackReader.
                      (InputStreamReader. (PipedInputStream. input)))
              stdout (OutputStreamWriter.
                       (proxy [java.io.ByteArrayOutputStream] []
                         (flush []
                           (jsobject-call applet out (str this))
                           (.reset this))))
              stderr (PrintWriter.
                       (OutputStreamWriter.
                         (proxy [java.io.ByteArrayOutputStream] []
                           (flush []
                             (jsobject-call applet err (str this))
                             (.reset this))))
                       true)
              thread (Thread. (partial my-repl applet stdin stdout stderr))]
          (.start thread))))
    input))

(defn -write
  "Write a string to the given stream."
  [applet stream string]
  (.write stream (.getBytes string)))

(defn -generateKey
  [applet f]
  (.execute (:priv-executor @(.state applet))
    (fn []
      (let [keypair (generate-rsa-keypair! (:random @(.state applet)))
            pkcs8 (.getEncoded (.getPrivate keypair))]
        (jsobject-call applet f (base64-encode pkcs8))))))

(defn -startPeer
  [applet b64key f]
  (.execute (:priv-executor @(.state applet))
    (fn []
      (try
        (let [pkcs8 (base64-decode b64key)
              private-key (make-rsa-private-key pkcs8)
              public-key (make-rsa-public-key (.getModulus private-key)
                           (.getPublicExponent private-key))
              peer (new-peer {:random (:random @(.state applet))
                              :public-key public-key
                              :private-key private-key})]
          (.start (:selector-thread peer))
          (jsobject-call applet f peer))
        (catch InvalidKeySpecException e
          (jsobject-call applet f "badkey"))
        (catch Exception e
          (.printStackTrace e (System/err))
          (jsobject-call applet f nil))))))

(defn -configureTCP
  [applet peer port]
  ;; TODO: make TCP reconfigurable
  (.execute (:priv-executor @(.state applet))
    (fn []
      (activate-tcp! peer port)
      (configure-inet-addresses! peer "tcp" (get-local-addresses) port))))

(defn transport-addresses-watcher
  [applet peer f watched-agent old-state new-state]
  (when-not (= old-state new-state)
    (jsobject-call applet f
      (json-str
        {"peerChanged"
         [(encode-ascii-hash (:id peer))
          (merge-transport-addresses {}
            (for [address (list-transport-addresses new-state)]
              (dissoc address :send-time :challenge)))]}))))

(defn remote-peers-watcher
  [applet f watched-agent old-state new-state]
  (let [peers-added (apply dissoc new-state (keys old-state))
        peers-removed (apply dissoc old-state (keys new-state))]
    (doseq [peer (vals peers-added)]
      (add-watch (:transport-addresses-agent peer) f
        (partial transport-addresses-watcher applet peer)))
    (when-not (and (empty? peers-added) (empty? peers-removed))
      (jsobject-call applet f
        (json-str
          {"peersAdded" (map encode-ascii-hash (keys peers-added))
           "peersRemoved" (map encode-ascii-hash (keys peers-removed))})))))

(defn -watchPeers
  [applet peer f]
  (.execute (:priv-executor @(.state applet))
    (fn []
      (add-watch (:remote-peers-agent peer) f
        (partial remote-peers-watcher applet))
      (doseq [remote-peer @(:remote-peers-agent peer)]
        (add-watch (:transport-addresses-agent remote-peer) f
          (partial transport-addresses-watcher applet remote-peer)))
      (add-watch (:transport-addresses-agent peer) f
        (partial transport-addresses-watcher applet peer)))))

(defn -fetchHostlist
  [applet peer url]
  (.execute (:priv-executor @(.state applet))
    (fn []
      (download-hostlist! (partial admit-hello! peer) url))))
