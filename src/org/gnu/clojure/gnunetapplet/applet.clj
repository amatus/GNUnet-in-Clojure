(ns org.gnu.clojure.gnunetapplet.applet
  (:use (org.gnu.clojure.gnunet crypto exception)
    clojure.contrib.monads)
  (:use [clojure.main :only (repl)])
  (:import
    clojure.lang.LineNumberingPushbackReader
    (java.io ByteArrayOutputStream InputStreamReader OutputStreamWriter
      PipedInputStream PipedOutputStream PrintWriter)
    (netscape.javascript JSObject JSException))
  (:gen-class
   :extends java.applet.Applet
   :state state
   :init ctor
   :main false
   :methods [[ver [] String]
             [in [String] Void]]))

(defn -ctor
  "The job of this constructor is to initialize state. The rest of the
   initalization happens in the Applet init method."
  []
  [[] (agent {})])

(defn my-repl
  [applet]
  (.setContextClassLoader (Thread/currentThread)
    (.getClassLoader (.getClass applet)))
  (let [input (PipedOutputStream.)
        stdin (LineNumberingPushbackReader.
                (InputStreamReader.
                  (PipedInputStream. input)))
        stdout (OutputStreamWriter.
                 (proxy [ByteArrayOutputStream] []
                   (flush []
                     (let [output (str this)]
                       (.reset this)
                       (try
                         (.call (JSObject/getWindow applet)
                           "out" (object-array [output]))
                         (catch JSException e nil))))))
        stderr (PrintWriter.
                 (OutputStreamWriter.
                   (proxy [ByteArrayOutputStream] []
                     (flush []
                       (let [output (str this)]
                         (.reset this)
                         (try
                           (.call (JSObject/getWindow applet)
                             "err" (object-array [output]))
                           (catch JSException e nil)))))))]
    (send (.state applet)
      (fn [state]
        (assoc state :input input)))
    (with-bindings {#'*in* stdin #'*out* stdout #'*err* stderr} (repl))))

(defn -init
  [this]
  (let [thread (Thread. (partial my-repl this))]
    (.start thread)
    (send (.state this)
      (fn [state]
        (assoc state :repl-thread thread)))))

(defn -ver
  [this]
  "0.5")

(defn -in
  [this string]
  (when-let [input (:input (deref (.state this)))]
    (.write input (.getBytes string))))
