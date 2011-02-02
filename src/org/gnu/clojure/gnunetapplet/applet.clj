(ns org.gnu.clojure.gnunetapplet.applet
  (:use clojure.contrib.monads
    [clojure.main :only (repl)]
    (org.gnu.clojure.gnunet crypto exception))
  (:import
    clojure.lang.LineNumberingPushbackReader
    (java.io InputStreamReader OutputStreamWriter
      PipedInputStream PipedOutputStream PrintWriter)
    (netscape.javascript JSObject JSException))
  (:gen-class
   :extends java.applet.Applet
   :state state
   :init ctor
   :main false
   :set-context-classloader true
   :methods [[ver [] String]
             [write [String] Void]]))

(def applet-ns *ns*)

(defn -ctor
  "The job of this constructor is to initialize state. The rest of the
   initalization happens in the Applet init method."
  []
  [[] (agent {})])

(defn jscall
  [applet f & args]
  (try
    (.call (JSObject/getWindow applet) f (object-array args))
    (catch JSException e
      (.printStackTrace e))))

(defn my-repl
  [applet]
  (.setContextClassLoader (Thread/currentThread)
    (.getClassLoader (.getClass applet)))
  (let [input (PipedOutputStream.)
        in (LineNumberingPushbackReader.
             (InputStreamReader. (PipedInputStream. input)))
        out (OutputStreamWriter.
              (proxy [java.io.ByteArrayOutputStream] []
                (flush []
                  (jscall applet "out" (str this))
                  (.reset this))))
        err (PrintWriter.
              (OutputStreamWriter.
                (proxy [java.io.ByteArrayOutputStream] []
                  (flush []
                    (jscall applet "err" (str this))
                    (.reset this))))
              true)]
    (send (.state applet) #(assoc % :input input))
    (declare *applet*)
    (with-bindings {#'*in* in
                    #'*out* out
                    #'*err* err
                    #'*ns* applet-ns
                    #'*applet* applet}
      (repl))))

(defn -init
  [this]
  (let [thread (Thread. (partial my-repl this))]
    (.start thread)
    (send (.state this) #(assoc % :repl-thread thread))))

(defn -ver
  [this]
  "0.12")

(defn -write
  [this string]
  (when-let [input (:input (deref (.state this)))]
    (.write input (.getBytes string))))
