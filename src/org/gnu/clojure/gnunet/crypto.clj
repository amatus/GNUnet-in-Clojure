(ns org.gnu.clojure.gnunet.crypto
  (:use (org.gnu.clojure.gnunet parser message)
    clojure.contrib.monads clojure.test)
  (:import (java.security KeyPairGenerator KeyFactory MessageDigest Signature)
    (java.security.spec RSAKeyGenParameterSpec RSAPublicKeySpec
                        RSAPrivateCrtKeySpec)
    java.math.BigInteger
    javax.crypto.Cipher))

(def signature-size 256)

(defn encode-signed
  [purpose inner-material]
  (concat
    (encode-int32 (+ 8 (count inner-material)))
    (encode-int32 purpose)
    inner-material))

(defn parse-signed
  "Produces a parser for a signed portion of a GNUnet message given a parser for
   the contained signed material. The produced parser will fail if the given
   parser does not successfully consume the entire signed material."
  [signed-material-parser]
  (fn
    [input]
    (when-let [[[size purpose inner-material] residue]
               ((domonad parser-m [size parse-uint32
                                   :when (<= 8 size)
                                   purpose parse-uint32
                                   inner-material (items (- size 8))]
                  [size purpose inner-material]) input)]
      (when-let [[parsed inner-residue]
                 (signed-material-parser inner-material)]
        (if (empty? inner-residue)
          [{:purpose purpose
            :signed-material (take size input)
            :parsed parsed} residue])))))

(defn generate-rsa-keypair
  "Generate a 2048 bit RSA keypair."
  []
  (let [rsa (KeyPairGenerator/getInstance "RSA")
        spec (RSAKeyGenParameterSpec. 2048 (bigint 257))]
    (.initialize rsa spec)
    (.generateKeyPair rsa)))

(defn make-rsa-public-key
  "Make an RSA public key from a modulus and exponent."
  [modulus exponent]
  (let [keyfactory (KeyFactory/getInstance "RSA")
        keyspec (RSAPublicKeySpec. modulus exponent)]
    (.generatePublic keyfactory keyspec)))

(defn make-rsa-private-key
  "Make an RSA private key from PKCS#1 values."
  [e n p q d u dp dq]
  (let [keyfactory (KeyFactory/getInstance "RSA")
        keyspec (RSAPrivateCrtKeySpec. n e d p q dp dq u)]
    (.generatePrivate keyfactory keyspec)))

(defn rsa-sign
  [private-key byte-seq]
  (.sign (doto (Signature/getInstance "SHA512withRSA")
           (.initSign private-key)
           (.update (byte-array byte-seq)))))

(defn rsa-verify
  [public-key byte-seq signature]
  (.verify (doto (Signature/getInstance "SHA512withRSA")
             (.initVerify public-key)
             (.update (byte-array byte-seq)))
    (byte-array signature)))

(defn rsa-encrypt!
  [rsa-key byte-seq]
  (.doFinal (doto (Cipher/getInstance "RSA")
              (.init Cipher/ENCRYPT_MODE rsa-key))
    (byte-array byte-seq)))

(defn rsa-decrypt
  [rsa-key byte-seq]
  (.doFinal (doto (Cipher/getInstance "RSA")
              (.init Cipher/DECRYPT_MODE rsa-key))
    (byte-array byte-seq)))

(defn sha-512
  "Compute the SHA-512 digest of a sequence of bytes."
  [byte-seq]
  (.digest (MessageDigest/getInstance "SHA-512") (byte-array byte-seq)))

(def rsa-modulus-length 256)
(def rsa-exponent-length 2)
(def rsa-key-length (+ rsa-modulus-length rsa-exponent-length))

(defn encode-rsa-public-key
  "Convert an RSA public key to a sequence of bytes in gnunet format."
  [public-key]
  (let [modulus (encode-int (.getModulus public-key))
        modulus-len (count modulus)
        exponent (encode-int (.getPublicExponent public-key))
        exponent-len (count exponent)]
    (concat
      (encode-int16 (+ rsa-key-length 4))
      (encode-int16 rsa-modulus-length)
      (repeat (- rsa-modulus-length modulus-len) (byte 0))
      modulus
      (repeat (- rsa-exponent-length exponent-len) (byte 0))
      exponent
      (encode-int16 0))))

(def parse-rsa-public-key
  (domonad parser-m [len parse-uint16
                     sizen parse-uint16
                     n (parse-uint sizen)
                     e (parse-uint (- len sizen 4))
                     :let [public-key (try (make-rsa-public-key n e)
                                        (catch Exception e nil))]
                     :when public-key
                     padding parse-uint16
                     :when (== 0 padding)]
    public-key))

(with-test
(defn random-int
  "Return a cryptographically weak random non-negative integer of the given
   bit-length."
  [bit-length seed]
  {:pre [(> bit-length 0)]}
  (let [cnt (quot (+ bit-length 511) 512)
        hashes (iterate sha-512 seed)
        number (BigInteger. 1 (byte-array (mapcat identity (take cnt hashes))))
        len (.bitLength number)
        number (reduce bit-clear number (range (dec len) (dec bit-length) -1))]
    [number (nth hashes cnt)]))
(is (= (let [[n seed] (random-int 1024 (sha-512 []))]
         [n (vec seed)])
       [145722097586741401146081933101625908822609966371134029821236387730376760429245348048227251733217120026252986740857779434920617271166036248533631595465678498079543252354969108228859509711652038086980961685030673985343697554674529134136563684623116336979340330220033374478392520298004708077375018922611329202505
        [-83 -57 -58 -86 82 42 91 -29 -56 -97 -36 -125 47 5 -57 120 48 -112 51
         -103 26 113 29 126 -80 46 88 13 -23 -59 -15 49 -34 50 54 -99 -61 -106
         -2 37 18 -103 -85 -98 -58 -4 33 -13 118 -112 125 -121 -43 43 19 11 -113
         -116 59 14 37 66 56 2]])))
  
(defn fermat-compositeness-test
  "Perform Fermat's Compositeness Test on the given bigint."
  [number]
  (not (== 1 (.modPow (bigint 2) (dec number) number))))

(defn miller-rabin-compositeness-test
  "Perform the Miller-Rabin Compositeness Test on the given bigint with the
   given number of rounds. This version uses a witness of 2 for the first
   round."
  [n steps seed]
  (let [bit-length (.bitLength n)
        nminus1 (dec n)
        k (.getLowestSetBit nminus1)
        q (bit-shift-right nminus1 k)]
    (loop [step 0 seed seed]
      (if (>= step steps)
        [false seed]
        (let [[x seed] (if (zero? step)
                         [(bigint 2) seed]
                         (random-int (dec bit-length) seed))
              y (.modPow x q n)]
          (if (or (== 1 y) (== nminus1 y))
            (recur (inc step) seed)
            (if (loop [g (next (take k (iterate #(.modPow % (bigint 2) n) y)))]
                  (cond
                    (nil? g) false
                    (== 1 (first g)) false
                    (== nminus1 (first g)) true
                    :else (recur (next g))))
              (recur (inc step) seed)
              [true seed])))))))

(def small-primes)

(with-test
(defn generate-prime
  "Generates a cryptographically weak random prime of the given bit-length."
  [bit-length seed]
  {:pre [(>= bit-length 32)]}
  (loop [seed seed]
    (let [[prime seed] (random-int bit-length seed)
          prime (bit-set prime (dec bit-length))
          prime (bit-set prime (- bit-length 2))
          prime (bit-set prime 0)
          mods (map (partial rem prime) small-primes)
          [prime seed] (loop [step 0 seed seed]
                         (if (> step 20000)
                           [nil seed]
                           (if (not-any?
                                 zero?
                                 (map #(rem (+ step %1) %2) mods small-primes))
                             (let [prime (+ prime step)]
                               (if (fermat-compositeness-test prime)
                                 (recur (inc step) seed)
                                 (let [[result seed]
                                       (miller-rabin-compositeness-test
                                         prime
                                         5
                                         seed)]
                                   (if result
                                     (recur (inc step) seed)
                                     [prime seed]))))
                             (recur (inc step) seed))))]
      (if prime [prime seed] (recur seed)))))
(is (= (let [[prime seed] (generate-prime 1024 (sha-512 []))]
         [prime (vec seed)])
      [145722097586741401146081933101625908822609966371134029821236387730376760429245348048227251733217120026252986740857779434920617271166036248533631595465678498079543252354969108228859509711652038086980961685030673985343697554674529134136563684623116336979340330220033374478392520298004708077375018922611329203201
       [-110 35 7 6 -114 -46 -94 -76 41 94 76 110 -116 9 -39 30 71 48 -55 -9 -95
        -9 -117 -6 -31 -47 117 125 71 73 25 95 -100 50 123 -64 86 31 101 53 -89
        33 -38 70 -77 15 -85 44 18 -5 -29 -4 -120 0 114 -79 81 -127 -102 102 126
        -14 5 60]])))

(with-test
(defn generate-kblock-key
  "Generates an RSA private key of a given bit-length."
  [bit-length seed]
  {:pre [(even? bit-length)]}
  (loop [seed seed]
    (let [[n p q seed] (first
                         (filter #(== bit-length (.bitLength (first %)))
                           (iterate #(let [[_ _ _ seed] %
                                           [p seed] (generate-prime
                                                      (quot bit-length 2) seed)
                                           [q seed] (generate-prime
                                                      (quot bit-length 2) seed)
                                           [p q] (sort [p q])
                                           n (* p q)]
                                       [n p q seed])
                             [(bigint 0) 0 0 seed])))
          t1 (dec p)
          t2 (dec q)
          phi (* t1 t2)
          g (.gcd t1 t2)
          f (quot phi g)
          e (bigint (first (filter #(== 1 (.gcd phi (bigint %)))
                             (iterate (partial + 2) 257))))]
      (let [private-key (try
                          (let [d (.modInverse e f)
                                u (.modInverse p q)]
                            (make-rsa-private-key
                              e
                              n
                              p
                              q
                              d
                              u
                              (.mod d t1)
                              (.mod d t2)))
                          (catch Exception e nil))]
        (if private-key private-key (recur seed))))))
(is (=
      (encode-rsa-public-key
        (generate-kblock-key 1024 (sha-512 (.getBytes "X" "utf-8"))))
      [1 6 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
       0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
       0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
       0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 -73 60 33 95 122 94 107 9 -66
       -59 87 19 -55 1 120 108 9 50 74 21 9 -128 -32 20 -67 -80 -48 68 38 -109
       73 41 -61 -76 -105 26 -105 17 -81 84 85 83 108 -42 -18 -72 -65 -96 4 -18
       -112 73 114 -89 55 69 95 83 -57 82 -104 125 -116 -126 -73 85 -68 2 -120
       43 68 -107 12 74 -51 -63 103 43 -89 76 59 -108 -40 26 76 30 -93 -41 78
       119 0 -82 85 -108 -61 -92 -13 -59 89 -28 -65 -14 -33 104 68 -6 -61 2 -28
       -74 97 117 -31 77 -56 -70 -45 -50 68 40 29 47 -20 26 26 -66 -16 99 1 1 0
       0])))

(def small-primes [
  3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43,
  47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101,
  103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
  157, 163, 167, 173, 179, 181, 191, 193, 197, 199,
  211, 223, 227, 229, 233, 239, 241, 251, 257, 263,
  269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
  331, 337, 347, 349, 353, 359, 367, 373, 379, 383,
  389, 397, 401, 409, 419, 421, 431, 433, 439, 443,
  449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
  509, 521, 523, 541, 547, 557, 563, 569, 571, 577,
  587, 593, 599, 601, 607, 613, 617, 619, 631, 641,
  643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
  709, 719, 727, 733, 739, 743, 751, 757, 761, 769,
  773, 787, 797, 809, 811, 821, 823, 827, 829, 839,
  853, 857, 859, 863, 877, 881, 883, 887, 907, 911,
  919, 929, 937, 941, 947, 953, 967, 971, 977, 983,
  991, 997, 1009, 1013, 1019, 1021, 1031, 1033,
  1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091,
  1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151,
  1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213,
  1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277,
  1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307,
  1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399,
  1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451,
  1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493,
  1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559,
  1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609,
  1613, 1619, 1621, 1627, 1637, 1657, 1663, 1667,
  1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733,
  1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789,
  1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871,
  1873, 1877, 1879, 1889, 1901, 1907, 1913, 1931,
  1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997,
  1999, 2003, 2011, 2017, 2027, 2029, 2039, 2053,
  2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111,
  2113, 2129, 2131, 2137, 2141, 2143, 2153, 2161,
  2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243,
  2251, 2267, 2269, 2273, 2281, 2287, 2293, 2297,
  2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357,
  2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411,
  2417, 2423, 2437, 2441, 2447, 2459, 2467, 2473,
  2477, 2503, 2521, 2531, 2539, 2543, 2549, 2551,
  2557, 2579, 2591, 2593, 2609, 2617, 2621, 2633,
  2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687,
  2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729,
  2731, 2741, 2749, 2753, 2767, 2777, 2789, 2791,
  2797, 2801, 2803, 2819, 2833, 2837, 2843, 2851,
  2857, 2861, 2879, 2887, 2897, 2903, 2909, 2917,
  2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999,
  3001, 3011, 3019, 3023, 3037, 3041, 3049, 3061,
  3067, 3079, 3083, 3089, 3109, 3119, 3121, 3137,
  3163, 3167, 3169, 3181, 3187, 3191, 3203, 3209,
  3217, 3221, 3229, 3251, 3253, 3257, 3259, 3271,
  3299, 3301, 3307, 3313, 3319, 3323, 3329, 3331,
  3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391,
  3407, 3413, 3433, 3449, 3457, 3461, 3463, 3467,
  3469, 3491, 3499, 3511, 3517, 3527, 3529, 3533,
  3539, 3541, 3547, 3557, 3559, 3571, 3581, 3583,
  3593, 3607, 3613, 3617, 3623, 3631, 3637, 3643,
  3659, 3671, 3673, 3677, 3691, 3697, 3701, 3709,
  3719, 3727, 3733, 3739, 3761, 3767, 3769, 3779,
  3793, 3797, 3803, 3821, 3823, 3833, 3847, 3851,
  3853, 3863, 3877, 3881, 3889, 3907, 3911, 3917,
  3919, 3923, 3929, 3931, 3943, 3947, 3967, 3989,
  4001, 4003, 4007, 4013, 4019, 4021, 4027, 4049,
  4051, 4057, 4073, 4079, 4091, 4093, 4099, 4111,
  4127, 4129, 4133, 4139, 4153, 4157, 4159, 4177,
  4201, 4211, 4217, 4219, 4229, 4231, 4241, 4243,
  4253, 4259, 4261, 4271, 4273, 4283, 4289, 4297,
  4327, 4337, 4339, 4349, 4357, 4363, 4373, 4391,
  4397, 4409, 4421, 4423, 4441, 4447, 4451, 4457,
  4463, 4481, 4483, 4493, 4507, 4513, 4517, 4519,
  4523, 4547, 4549, 4561, 4567, 4583, 4591, 4597,
  4603, 4621, 4637, 4639, 4643, 4649, 4651, 4657,
  4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729,
  4733, 4751, 4759, 4783, 4787, 4789, 4793, 4799,
  4801, 4813, 4817, 4831, 4861, 4871, 4877, 4889,
  4903, 4909, 4919, 4931, 4933, 4937, 4943, 4951,
  4957, 4967, 4969, 4973, 4987, 4993, 4999,
  ])
