(ns org.gnu.clojure.gnunet.crypto
  (:use (org.gnu.clojure.gnunet parser message primes)
    clojure.contrib.monads clojure.test)
  (:import java.math.BigInteger
    java.util.zip.CRC32
    (java.security KeyPairGenerator KeyFactory MessageDigest Signature)
    (java.security.spec RSAKeyGenParameterSpec RSAPublicKeySpec
                        RSAPrivateCrtKeySpec)
    (javax.crypto Cipher KeyGenerator SecretKeyFactory Mac)
    (javax.crypto.spec SecretKeySpec IvParameterSpec)))

(def signature-size 256)
(def aes-key-size 32)
(def aes-iv-size (/ aes-key-size 2))

(defn sha-512
  "Compute the SHA-512 digest of a sequence of bytes."
  [byte-seq]
  (.digest (MessageDigest/getInstance "SHA-512") (byte-array byte-seq)))

(defn hmac-sha-512
  [key-seq byte-seq]
  (let [hmac-key (SecretKeySpec. (byte-array key-seq) "HmacSHA512")
        hmac (doto (Mac/getInstance "HmacSHA512") (.init hmac-key))]
    (.doFinal hmac (byte-array byte-seq))))

(defn hmac-sha-256
  [key-seq byte-seq]
  (let [hmac-key (SecretKeySpec. (byte-array key-seq) "HmacSHA256")
        hmac (doto (Mac/getInstance "HmacSHA256") (.init hmac-key))]
    (.doFinal hmac (byte-array byte-seq))))

(with-test
(defn hkdf
  "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
   http://tools.ietf.org/html/rfc5869"
  [hmac-extract hmac-expand key-material salt info output-length]
  (let [salt (if (empty? salt) [(byte 0)] salt)
        pseudorandom-key (hmac-extract salt key-material)
        generator (fn [x]
                    (let [[input counter] x
                          counter (.byteValue (inc counter))]
                      [(hmac-expand pseudorandom-key
                         (concat input info [counter]))
                       counter]))
        keying-material (mapcat first (iterate generator [[] 0]))]
    (take output-length keying-material)))
;; RFC 5869 A.1. Test Case 1
(is (= (let [ikm (encode-int 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b)
             salt (concat [(byte 0)] (encode-int 0x0102030405060708090a0b0c))
             info (encode-int 0xf0f1f2f3f4f5f6f7f8f9)
             l 42]
         (hkdf hmac-sha-256 hmac-sha-256 ikm salt info l))
      (encode-int 0x3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865)))
;; RFC 5869 A.3. Test Case 3
(is (= (let [ikm (encode-int 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b)
             salt []
             info []
             l 42]
         (hkdf hmac-sha-256 hmac-sha-256 ikm salt info l))
      (encode-int 0x8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8))))

(defn make-aes-key
  [byte-seq]
  (.generateSecret (SecretKeyFactory/getInstance "AES")
    (SecretKeySpec. (byte-array byte-seq) "AES")))

(defn crc32
  [byte-seq]
  (.getValue (doto (CRC32.) (.update (byte-array byte-seq)))))

(defn encode-aes-key
  [aes-key]
  (concat
    (.getEncoded aes-key)
    (encode-int32 (crc32 (.getEncoded aes-key)))))

(def parse-aes-key
  (domonad parser-m [aes-key (items aes-key-size)
                     checksum parse-uint32
                     :when (= checksum (crc32 aes-key))]
    (make-aes-key aes-key)))

(defn generate-aes-key!
  [random]
  (.generateKey (doto (KeyGenerator/getInstance "AES")
                  (.init (* 8 aes-key-size) random))))

(defn derive-aes-iv
  [aes-key salt context]
  (IvParameterSpec.
    (byte-array (hkdf hmac-sha-512 hmac-sha-256
                  (.getEncoded aes-key) salt context aes-iv-size))))

(with-test
(defn aes-encrypt
  [aes-key iv byte-seq]
  (.doFinal (doto (Cipher/getInstance "AES/CFB/NoPadding")
              (.init Cipher/ENCRYPT_MODE aes-key iv))
    (byte-array byte-seq)))
;; Test case from gnunet test_crypto_aes.c
(is (= (let [plaintext (map #(.byteValue %)
                         [29, 128, 192, 253, 74, 171, 38, 187, 84, 219, 76, 76, 209, 118, 33, 249,
                          172, 124, 96, 9, 157, 110, 8, 215, 200, 63, 69, 230, 157, 104, 247, 164])
             raw-key (map #(.byteValue %)
                       [106, 74, 209, 88, 145, 55, 189, 135, 125, 180, 225, 108, 183, 54, 25,
                        169, 129, 188, 131, 75, 227, 245, 105, 10, 225, 15, 115, 159, 148, 184,
                        34, 191])
             aes-key (make-aes-key raw-key)
             iv (IvParameterSpec. (.getBytes "testtesttesttest" "UTF-8"))]
         (seq (aes-encrypt aes-key iv plaintext)))
      (map #(.byteValue %)
        [167, 102, 230, 233, 127, 195, 176, 107, 17, 91, 199, 127, 96, 113, 75,
         195, 245, 217, 61, 236, 159, 165, 103, 121, 203, 99, 202, 41, 23, 222, 25,
         102]))))

(with-test
(defn aes-decrypt
  [aes-key iv byte-seq]
  (.doFinal (doto (Cipher/getInstance "AES/CFB/NoPadding")
              (.init Cipher/DECRYPT_MODE aes-key iv))
    (byte-array byte-seq)))
;; Test case from gnunet test_crypto_aes.c
(is (= (let [ciphertext (map #(.byteValue %)
                          [167, 102, 230, 233, 127, 195, 176, 107, 17, 91, 199, 127, 96, 113, 75,
                           195, 245, 217, 61, 236, 159, 165, 103, 121, 203, 99, 202, 41, 23, 222, 25,
                           102])
             raw-key (map #(.byteValue %)
                       [106, 74, 209, 88, 145, 55, 189, 135, 125, 180, 225, 108, 183, 54, 25,
                        169, 129, 188, 131, 75, 227, 245, 105, 10, 225, 15, 115, 159, 148, 184,
                        34, 191])
             aes-key (make-aes-key raw-key)
             iv (IvParameterSpec. (.getBytes "testtesttesttest" "UTF-8"))]
         (seq (aes-decrypt aes-key iv ciphertext)))
      (map #(.byteValue %)
        [29, 128, 192, 253, 74, 171, 38, 187, 84, 219, 76, 76, 209, 118, 33, 249,
         172, 124, 96, 9, 157, 110, 8, 215, 200, 63, 69, 230, 157, 104, 247, 164]))))

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
  (domonad parser-m
    [encoded-size (items 4)
     :let [size (long (decode-uint encoded-size))] 
     :when (<= 8 size)
     encoded-purpose (items 4)
     :let [purpose (long (decode-uint encoded-purpose))]
     inner-material (items (- size 8))
     :let [result (signed-material-parser inner-material)]
     :when result
     :let [[parsed residue] result]
     :when (empty? residue)]
    {:purpose purpose
     :signed-material (concat encoded-size encoded-purpose inner-material)
     :parsed parsed}))

(defn generate-rsa-keypair!
  "Generate a 2048 bit RSA keypair."
  [random]
  (let [rsa (KeyPairGenerator/getInstance "RSA")
        spec (RSAKeyGenParameterSpec. 2048 (bigint 257))]
    (.initialize rsa spec random)
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
        ;; Swap p and q, in java q < p
        keyspec (RSAPrivateCrtKeySpec. n e d q p dq dp u)]
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
  [rsa-key byte-seq random]
  (.doFinal (doto (Cipher/getInstance "RSA")
              (.init Cipher/ENCRYPT_MODE rsa-key random))
    (byte-array byte-seq)))

(defn rsa-decrypt
  [rsa-key byte-seq]
  (try
    (.doFinal (doto (Cipher/getInstance "RSA")
                (.init Cipher/DECRYPT_MODE rsa-key))
      (byte-array byte-seq))
    (catch Exception e nil)))


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
        number (BigInteger. 1 (byte-array (apply concat (take cnt hashes))))
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
