(ns org.gnu.clojure.gnunet.parser
  (:use clojure.contrib.monads))

(def parser-m (state-t maybe-m))

(defn parser-m-until
  "An optimized implementation of m-until for the parser monad that
   replaces recursion by a loop."
  [p f x]
  (letfn [(until [p f x s]
            (if (p x)
              [x s]
              (when-let [xs ((f x) s)]
                (recur p f (first xs) (second xs)))))]
    (fn [s] (until p f x s))))

(defn item
  "Parser which returns the first item of input."
  [xs]
  (when (not (empty? xs)) [(first xs) (rest xs)]))

(defn satisfy
  "Produces a parser that matches an item which satisfies the given predicate."
  [p]
  (domonad parser-m [x item
                     :when (p x)]
    x))

(defn match-one
  "Match the first in a list of parsers."
  [& mvs]
  (with-monad parser-m
    (apply m-plus mvs)))

(defn optional
  "Makes a parser optional."
  [mv]
  (with-monad parser-m
    (m-plus mv (m-result nil))))

(defn none-or-more
  "Makes a parser repeat none or more times."
  [mv]
  (fn [s]
    (let [xs ((parser-m-until
                    first
                    #(fn [s]
                       (if-let [x (mv s)]
                         [[false (conj (second %) (first x))] (second x)]
                         [[true (second %)] s]))
                    [false []]) s)]
      [(second (first xs)) (second xs)])))

(defn one-or-more
  "Makes a parser repeat one or more times."
  [mv]
  (domonad parser-m [x mv
                     xs (none-or-more mv)]
    (cons x xs)))

(defn n-times
  "Makes a parser repeat exactly n times."
  [mv n]
  (fn [s]
    (when-let [xs ((parser-m-until
                    #(<= n (first %))
                    #(fn [s]
                       (when-let [xs (mv s)]
                         [[(inc (first %)) (conj (second %) (first xs))]
                          (second xs)]))
                    [0 []]) s)]
      [(second (first xs)) (second xs)])))

(def
  #^{:doc "Produces a parser that matches a number of items."}
  items (partial n-times item))
