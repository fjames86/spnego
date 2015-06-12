;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

                                                             
                                 
;; https://msdn.microsoft.com/en-us/library/ms995330.aspx
;; http://blogs.msdn.com/b/openspecification/archive/2011/06/24/authentication-101.aspx
;; http://tools.ietf.org/html/rfc4178

;; basically this wraps NTLM and Kerberos, negotiating whether to use Kerberos (if possible)
;; or falling back to NTLM otherwise. So it requires access to the underlying NTLM and Kerberos
;; implementations.

(defpackage #:spnego
  (:use #:cl))

(in-package #:spnego)

(defparameter *spnego-oid* '(1 3 6 1 5 5 2)) 
(defparameter *ntlm-oid* '(1 3 6 1 4 1 311 2 2 10))

(defun encode-initial-context-token (stream message)
  (declare (type stream stream)
           (type vector message))
  (let ((octets (flexi-streams:with-output-to-sequence (s)
                  (cerberus::encode-oid s *spnego-oid*)
                  (write-sequence message s))))
    (cerberus::encode-identifier stream 0 :class :application :primitive nil)
    (cerberus::encode-length stream (length octets))
    (write-sequence octets stream)))

;; need a decode-initial-context-token as well
(defun decode-initial-context-token (stream)
  ;; WARNING: the Microsoft SSPI is known to generate a raw NTLM token sometimes instead of 
  ;; an SPNEGO token, i.e. it will start with "NTLMSSP..." instead of the ASN.1 identifer/length/oid octets.
  ;; We could try and detect that here rather than assuming it's always in the correct format.
  ;; For now though, let's just assume it really is in the correct format.
  (cerberus::decode-identifier stream) ;; tag=0, class=application
  (let* ((len (cerberus::decode-length stream))
         (bytes (nibbles:make-octet-vector len)))
    (read-sequence bytes stream)
    (flexi-streams:with-input-from-sequence (s bytes)
      ;; contents
      (let ((oid (cerberus::decode-oid s)))
        (unless (cerberus::oid-eql oid *spnego-oid*)
          (error "Token OID ~S not SPNEGO" oid)))
      (let ((v (nibbles:make-octet-vector (- len (file-position s)))))
        (read-sequence v s)
        v))))

(cerberus::defxtype mech-type ()
  ((stream)
   (cerberus::decode-oid stream))
  ((stream oid)
   (cerberus::encode-oid stream oid)))

(cerberus::defxtype mech-list ()
  ((stream)
   (cerberus::decode-sequence-of stream #'cerberus::decode-oid))
  ((stream list)
   (cerberus::encode-sequence-of stream #'cerberus::encode-oid list)))

(defvar *context-flags* 
  '((:deleg 1)
    (:mutual 2)
    (:replay 4)
    (:sequence 8)
    (:anon 16)
    (:conf 32)
    (:integ 64)))

(cerberus::defxtype context-flags ()
  ((stream)
   (cerberus::unpack-flags (cerberus::decode-bit-string stream) *context-flags*))
  ((stream flags)
   (cerberus::encode-bit-string stream (cerberus::pack-flags flags *context-flags*))))

(cerberus::defsequence neg-token-init ()
  (mech-types mech-list :tag 0)
  (flags context-flags :tag 1 :optional t)
  (token cerberus::asn1-octet-string :tag 2 :optional t)
  (mic cerberus::asn1-octet-string :tag 3 :optional t))

;; -----------------------------------
;; MS-SPNG defines an alternate version 
;; Looks like this is only used when the server initiates authentication
;; (cerberus::defsequence neg-hints ()
;;   (name cerberus::asn1-string :tag 0 :optional t)
;;   (address cerberus::asn1-octet-string :tag 1 :optional t))

;; (cerberus::defsequence neg-token-init2 ()
;;   (mech-types mech-list :tag 0)
;;   (flags context-flags :tag 1 :optional t)
;;   (token cerberus::asn1-octet-string :tag 2 :optional t)
;;   (hints neg-hints :tag 3 :optional t)
;;   (mic cerberus::asn1-octet-string :tag 4 :optional t))
;; -----------------------------------

(cerberus::defxtype neg-state ()
  ((stream)
   (let ((state (cerberus::decode-asn1-int32 stream)))
     (ecase state
       (0 :completed)
       (1 :incomplete)
       (2 :reject)
       (3 :request-mic))))
  ((stream state)
   (cerberus::encode-asn1-int32 stream
                                (ecase state
                                  (:completed 0)
                                  (:incomplete 1)
                                  (:reject 2)
                                  (:request-mic 3)))))

(cerberus::defsequence neg-token-resp ()
  (state neg-state :tag 0 :optional t)
  (mech mech-type :tag 1 :optional t)
  (token cerberus::asn1-octet-string :tag 2 :optional t)
  (mic cerberus::asn1-octet-string :tag 3 :optional t))

(cerberus::defxtype nego-token ()
  ((stream)  
   (let ((tag (cerberus::decode-identifier stream)))
     (cerberus::decode-length stream)
     (ecase tag 
       (0 (decode-neg-token-init stream))
       (1 (decode-neg-token-resp stream)))))
  ((stream obj)
   (etypecase obj
     (neg-token-init 
      (let ((bytes (flexi-streams:with-output-to-sequence (s)
                     (encode-neg-token-init s obj))))
        (cerberus::encode-identifier stream 0 :class :context :primitive nil)
        (cerberus::encode-length stream (length bytes))
        (write-sequence bytes stream)))
     (neg-token-resp
      (let ((bytes (flexi-streams:with-output-to-sequence (s)
                     (encode-neg-token-resp s obj))))
        (cerberus::encode-identifier stream 1 :class :context :primitive nil)
        (cerberus::encode-length stream (length bytes))
        (write-sequence bytes stream))))))

(defun pack (writer obj)
  (cerberus::pack writer obj))

(defun unpack (reader buffer)
  (cerberus::unpack reader buffer))


;; ----------------------- GSS Api -------------------------------------

(defclass spnego-credentials ()
  ((creds :initarg :creds :reader spnego-creds)
   (oid :initarg :oid :reader spnego-creds-oid)))

(defmethod glass:acquire-credentials ((type (eql :spnego)) principal &key)
  ;; just return the kerberos creds
  (handler-case 
      (let ((creds (glass:acquire-credentials :kerberos principal)))
        (make-instance 'spnego-credentials 
                       :creds creds 
                       :oid cerberus::*kerberos-oid*))
    (error (e)
      (warn "Kerberos failed: ~A" e)
      ;; fall back to NTLM is Kerberos fails
      (make-instance 'spnego-credentials 
                     :creds (glass:acquire-credentials :ntlm nil)
                     :oid *ntlm-oid*))))

(defclass spnego-context ()
  ((creds :initarg :creds :reader spnego-context-creds)
   (state :initform :init :initarg :state :accessor spnego-context-state)
   (context :initarg :context :initform nil :reader spnego-context-cxt)))

;; state can be:
;; :init ::= initial state (nothing done yet)
;; :negotiate ::= client has sent an initial negotiate token, server has received the negotiate token
;; :completed ::= client has sent a real token, server has received the real token

(defclass spnego-client-context (spnego-context)
  ())

(defmethod glass:initialize-security-context ((creds spnego-credentials) &key)
  ;; This is an initial negotiation request. Generate and pack an init token, 
  ;; wrapped with the spnego oid
  (multiple-value-bind (context token-buffer) (glass:initialize-security-context (spnego-creds creds))
    (let ((buffer (pack #'encode-initial-context-token
                        (pack #'encode-nego-token 
                              (make-neg-token-init :mech-types (list (spnego-creds-oid creds))
                                                   :flags nil
                                                   :token token-buffer)))))
      (values (make-instance 'spnego-client-context 
                             :creds creds
                             :state :negotiate
                             :context context)
              buffer))))


(defmethod glass:initialize-security-context ((cxt spnego-client-context) &key buffer)
  ;; a buffer is supplied, this means it is a second round of processing
  ;; the mechanism should be either NTLM or Kerberos
  ;; the buffer should be a nego-token-resp buffer 
  (let ((tok (flexi-streams:with-input-from-sequence (s buffer)
               (decode-nego-token s))))
    (declare (type neg-token-resp tok))
    ;; ensure that the mechanism is correct 
    (unless (cerberus::oid-eql (spnego-creds-oid (spnego-context-creds cxt))
                               (neg-token-resp-mech tok))
      (error "Neg token mech ~S doesn't match requested OID ~S" 
             (neg-token-resp-mech tok)
             (spnego-creds-oid (spnego-context-creds cxt))))

    ;; check the state, it SHOULD be :INCOMPLETE
    (unless (eq (neg-token-resp-state tok) :incomplete)
      (error "Unexpected token state ~S" (neg-token-resp-state tok)))

    ;; if this is NTLM then we proceed to the next stage of NTLM authentication
    ;; using the context we got in the first call
    ;; If doing Kerberos then we just repeat the process and try again
    (cond
      ((cerberus::oid-eql *ntlm-oid* (spnego-creds-oid (spnego-context-creds cxt)))
       ;; NTLM challenge message 
       (multiple-value-bind (ntlm-context resp-buff)
           (glass:initialize-security-context (spnego-context-cxt cxt)
                                              :buffer (neg-token-resp-token tok))
         (values (make-instance 'spnego-client-context
                                :creds (spnego-context-creds cxt)
                                :state :completed
                                :context ntlm-context)
                 (pack #'encode-nego-token 
                       (make-neg-token-resp :state :completed
                                            :mech (spnego-creds-oid (spnego-context-creds cxt))
                                            :token resp-buff)))))
      (t 
       ;; Kerberos, just get the ticket and try again
       (multiple-value-bind (krb-context resp-buff) 
           (glass:initialize-security-context (spnego-creds (spnego-context-creds cxt)))
         (values (make-instance 'spnego-client-context 
                                :creds (spnego-context-creds cxt)
                                :state :completed
                                :context krb-context)
                 (pack #'encode-nego-token 
                       (make-neg-token-resp :state :incomplete
                                            :mech (spnego-creds-oid (spnego-context-creds cxt))
                                            :token resp-buff
                                            :mic nil))))))))



(defclass spnego-server-context (spnego-context)
  ())

(defmethod glass:accept-security-context ((creds spnego-credentials) buffer &key)
  (let ((msg (flexi-streams:with-input-from-sequence (s buffer)
               (decode-initial-context-token s))))
    (let ((tok (flexi-streams:with-input-from-sequence (s msg)
                 (decode-nego-token s))))
      ;; ok, we've got the nego-token. this contains a list of mechanisms and an optimistic initial token
      ;; if we support one of the mechansims then just try the token directly 
      (let ((first (first (neg-token-init-mech-types tok))))
        ;; if the first one is ntlm or kerberos then we can proceed immediately, otherwise we reject outright
        (cond
          ((and (cerberus::kerberos-oid-p first) 
                (cerberus::oid-eql (spnego-creds-oid creds) cerberus::*kerberos-oid*))
           ;; the token is a kerberos token and the credentials are Kerberos credentials 
           (multiple-value-bind (context buffer) (glass:accept-security-context (spnego-creds creds) 
                                                                                (neg-token-init-token tok))
             (declare (ignore buffer))
             (values (make-instance 'spnego-server-context 
                                    :creds creds
                                    :context context
                                    :state :completed)
                     nil)))
          ((and (cerberus::oid-eql first *ntlm-oid*)
                (cerberus::oid-eql (spnego-creds-oid creds) *ntlm-oid*))
           ;; is an ntlm token and we are using ntlm 
           (multiple-value-bind (context buffer) (glass:accept-security-context (spnego-creds creds) 
                                                                                (neg-token-init-token tok))
             (declare (ignore buffer))
             (values (make-instance 'spnego-server-context 
                                    :creds creds
                                    :context context 
                                    :state :completed)
                     nil)))
          (t 
            (error 'glass:gss-error :major :bad-mech)))))))

;; for generating mutual authentication responses
;; (defmethod glass:accept-security-context ((context spnego-server-context) buffer &key)
;;   ;; if the context is provided then we are continuing a previously initialized context
;;   (ecase (spnego-context-state context)
;;     (:init (error "Context still in initial state"))
;;     (:negotiate 
;;      ;; we have already negotiated the supported authentication systems
;;      ;; the buffer is expected to be a real kerberos token
;;      (let ((tok (flexi-streams:with-input-from-sequence (s buffer)
;;                   (decode-nego-token s))))
;;        ;; tok should be a neg-token-resp
;;        (declare (type neg-token-resp tok))
;;        ;; assume it's a kerberos token and pass to cerberus
;;        (let ((cxt (glass:accept-security-context (spnego-creds (spnego-context-creds context)) 
;;                                                  (neg-token-resp-token tok))))
;;          (values (make-instance 'spnego-server-context 
;;                                 :state :completed
;;                                 :creds (spnego-context-creds context)
;;                                 :context cxt)
;;                  nil))))
;;     (:completed (error "Context completed"))))


(defmethod glass:context-principal-name ((context spnego-server-context) &key)
  ;; just call the underlying implementation
  (glass:context-principal-name (spnego-context-cxt context)))


;; (defmethod glass:get-mic ((context spnego-context) message &key)
;;   ;; just dispatch to the kerberos function
;;   nil)

;; (defmethod glass:verify-mic ((context spnego-context) message token &key)
;;   nil)

;; (defmethod glass:wrap ((context spnego-context) message &key)
;;   (glass:wrap (spnego-context-cxt 
;;   nil)

;; (defmethod glass:unwrap ((context spnego-context) message &key) 
;;   nil)


(defparameter *client-req-1* 
  #(96 130  5 224  6  6 43  6  1  5  5  2 160 130  5 212 48
130  5 208 160 48 48 46  6  9 42 134 72 130 247 18  1
 2  2  6  9 42 134 72 134 247 18  1  2  2  6 10 43
 6  1  4  1 130 55  2  2 30  6 10 43  6  1  4  1
130 55  2  2 10 162 130  5 154  4 130  5 150 96 130  5
146  6  9 42 134 72 134 247 18  1  2  2  1  0 110 130
 5 129 48 130  5 125 160  3  2  1  5 161  3  2  1 14
162  7  3  5  0 32  0  0  0 163 130  4  7 97 130  4
 3 48 130  3 255 160  3  2  1  5 161 13 27 11 69 88
83 69 81 85 73 46 67 79 77 162 19 48 17 160  3  2
 1  1 161 10 48  8 27  6 102 106 97 109 101 115 163 130
 3 210 48 130  3 206 160  3  2  1 23 161  3  2  1  3
162 130  3 192  4 130  3 188 250 224 128 113 49 74 150 44
221 187 99 207 96 173 120 192 160 217 127 184 59 246 92 132
174 229 233 82 54 202 176 184 145 17 171 35 229 39 57 223
104 217 56 40 191 92 12 239 253 111 28 32 55 149 203 140
52 28 184 164 203 144  9 203 123 28  5 114 35 165 22 117
191 16 160 133 66 68 231 84 16 57  2 140 253 50 52 35
190 211 158 177 225 16 27 120 171 115 226 186 78 191 37 235
194 160 12 53 250 170 242 30 179 79 154 114 30 62 43  4
139 200 253 175 58 37 172 42 224 185 80 118 121 213 61  2
224 34 188  0 108 41 169 46 34 171 132 222 233 115 252 49
113 20 218 153 129 88 218 30 173 25 54 81 195 102 115  3
34 195 233 223 222  5 104 213 214 71 222 35 187 203 114 30
204 236 37 223 117 196 249 237  0 160 175 188 166 29 64 183
 4 65 246 35 128 182 144 51 44 28 43 104 14 162 150 99
121 85 95  0 166 165 216 69 69 14 216 47 116 44 43 88
66 140 239 215 239 208 85 191 73  3 97 164 47 82 160 204
247 130 109 100 250 157  6 57 249 118 230 204 123 24 18 139
195 140 136 36 74 81 135 240 91 167 185 115 200 78 179 127
119 216 140 133 143 239 108 127 123 211 77 63 74 46 186 208
209 163 42 96 41 100 70 158 146 50 55 129 46 122 98 147
 5 233 165 202 101 128 201 68 155 77 189 94 126 84  0 105
139 90 66 175 68 32 114 108 144 120 12 193 118 220 79 224
201 117 38 105 247 133 38 147 124 10 224 230 58 65 173 86
194 188 88 250 226 217 152 140 237 217 74 182 77 174 40 98
252 123 106 126 160 39 137 141 88 97 244 233 114 149 22 234
134 154  4 246 49 67 180 60 230 163 209 25 188  7 38 56
54 56 136 178 128 136 191 134 54 173 208 50 236 135 108 95
74 100 239 163 51 128 40 71 186 177 251 163 119 121 163 157
45 204 52 243 246 237 33 17 21 239  4 51 246 144 98 146
215 146 87 182 90 104 248 233 209 213 201 64 248 190 87 46
55 168 108 210 203 156 116 95 141 236 213 249 14 64 117 35
229 79 104  5 238 20 240 190 143 55 44 187 146  3 118 241
125 236 18 23 53 138 30 164 13 42 133 181 177 22 62 21
50 144 182 197 80 196 81 123 248 123 214 177 54 251 211 128
170 169 231 196 233 236 207 215 241 163 236 209 66 234 210 59
227 192 237 93 196 13 193 21 72 172 117 208 99 28 184 90
215 198 130 79 73 120 187 120 183 114 11 175 28 251 183 139
105 16 83 237 117 128 211 178 171 114 169 175 211 221 34 66
244 150 172 89  1  7 86 38 153 204 232 73 141 86 109 56
193 43  9 229 155 50 235 126 236 234 136 236 61 118 45 97
14 75 213 224 138 64 39 166 40  7 249 111 77 164 36 201
177  3 217  3 17 18 209 80 49 41 156 80 108 59 75 53
53 232 235  8 29 171 140 100 197 21 31 61 119 69 22 67
24 181 246 217 61 132 245 14 249 191 142 170 212 92 252 127
68 239 82 27 76 39 12 151 70 204 175 96 163 119 237 233
65 239 232 201 235 236 202 180 12 51 71 47 233 213 72 43
159 234 82 207  8 237 133 143 197 151 42 124 94 240 119 254
78 179 48 47 124 149 20 22 36 14 34 144 46 143 247 20
171 13 223 50 137 205 61 209 63 54 170 104 193 252 222 118
168 246 232 161 174 120 206 218 202 77 90 238 80 238 42 33
155 42 162 105 129 69 39 16 172 179 65 242  6 200 140 190
78 219 197 84 62 77 120 151 249 157 160 250 101 89 34  2
 4 201 236 225 232 60 119 236 145 112 207 173 217 131 168 74
81 111  6 17 171 33 59 31 162 122 85 12 65 165 82 96
81 152 53 123 29 169 239 154 186 170 29 175 160 244 62 84
164 33 121 101 190 251 151 45 91 53 91 227 151 18 92 162
237 117 252 100 222 154 194 26 228 52 254 186 244 80 207 20
67 203 254 83 139 39 116 93 229 193 195 221 183 202 155 34
149  3 24 201 136 58 181 53 217 197 192 71 203 252 22 137
 6 51 100 214 195 43 38 75 248 68 162 34 27 207 159 212
158 221 68 163 164 130  1 91 48 130  1 87 160  3  2  1
23 162 130  1 78  4 130  1 74 226 27 136 184 251 190 234
216 243 191 53 242 239 146 30 138 89 120 243 38 197 93 11
114 77 43 145 75 129 169 236 67 127 161 172 95 243 225 83
15 141 228 173  8 24 176 116 45 218 61 182  9 14 124 163
11 181 122 244 55 140 26 245 93 12 16 175 196 208 27 81
47 141 107 132 228 235 131 250 113 23 216 170 155 114 153  2
96 113 94 80 35 31 48 112 252 95 177 37 23 113 164 68
217 142 211 100 231 136 236 16 176 15 178 117 105 197 42 154
232 164 123 69 17  4 129 249 107 146 85 94 44 130 131 95
89  7 133 239 117 141 170 169 214 203 137 97 174 183 61 243
242 129 130 216 241 17 108 246 46 188 103 19 171 248 113 47
140 98 183 181 85 226 161 87 248 147 232  7 38 78 228 127
214 42 160 137 73 48 178 164 130 162 46 145 189 150 184 154
201 179 139 102 91 249 81 122 56 247 105 26 199 153 74 129
209 89 41 219 148 61 246 43 15 151 26 116 182 112 23 168
222 129 51 17 85 146 128 251 192 99 221 249 154 43 197 170
34  1 26 204 229 136 82 95 34 196 54 154 232 77 94 250
173 73 152 200 132 124 76 34 254 11 158 14 180 198 128 232
113 230 232 192 70 131 223 32 156 148 236 83 48 150 192 223
212 187 150 43 255 98 25 32 27 99 33 69 52 228  6 103
57 75 26 93  0 183 117 186 169 210  2 146 49 92 119  3
65 220 17))

(defparameter *server-resp-1*
  #(161 120 48 118 160  3 10  1  1 161 11  6  9 42 134 72 130
247 18  1  2  2 162 98  4 96 96 94  6  9 42 134 72
134 247 18  1  2  2  3  0 126 79 48 77 160  3  2  1
 5 161  3  2  1 30 164 17 24 15 50 48 49 53 48 54
49 50 49 49 49 57 48 49 90 165  5  2  3 13 13 107
166  3  2  1 41 169 13 27 11 69 88 83 69 81 85 73
46 67 79 77 170 19 48 17 160  3  2  1  1 161 10 48
 8 27  6 102 106 97 109 101 115))

(defparameter *client-req-2*
  #(161 130  5 167 48 130  5 163 160  3 10  1  1 162 130  5 154
 4 130  5 150 96 130  5 146  6  9 42 134 72 134 247 18
 1  2  2  1  0 110 130  5 129 48 130  5 125 160  3  2
 1  5 161  3  2  1 14 162  7  3  5  0 32  0  0  0
163 130  4  7 97 130  4  3 48 130  3 255 160  3  2  1
 5 161 13 27 11 69 88 83 69 81 85 73 46 67 79 77
162 19 48 17 160  3  2  1  1 161 10 48  8 27  6 102
106 97 109 101 115 163 130  3 210 48 130  3 206 160  3  2
 1 23 161  3  2  1  3 162 130  3 192  4 130  3 188 142
69 40 154 142 190  4 106 81 84 180 121 109 125 250 35 151
206 145 23 236 132 22 110 190 34 125 156 183 27 162 95 134
 3 57 96 63 143 160 96 16 32 85 232 89 147 137 26 59
124 68 130 149 168 125 90 201 143 145 156 175 155 229 77 22
28 186 55 182 17 77 83 45  7 14 239 99 63 25 114 226
143  5 125 63 50 133 254 240 239 192 133 46 182  8 104 38
135 218 76 120 53 162 109 66 212 218 164 104 62 31 26 100
90 100  3 122 137 127 224 143 71 123 218 108 182 183 76 17
98 209 200 161 23 247 151 62 129 169 142 245 64 251 57 57
191 195 149 227 54 47 229 73 34 19 199 55 186 153 113 10
119 221  2 81 98 35 176 62 53 154  9 149 44 81 182 183
255 86 57 89 252 86 102 250 89 114 243  0 42 205 222 198
166 32 170 202 107  4 159 84 113 53 67 95 209 103 226 50
245 51 17 236 40 84 77 158 86 196 26 72 218 80 70 218
185 64 16 30 27 222 123 75 151 74 45 181 156 39 202 117
44 98 34 46 249 216 40  3 121 70 174 154 44 244 75 49
221 190 243 130 252 133  3  4 16 78  5 24  3 149 204 227
54  4 252 216 220 181 70 138 27 178 238 248 201 78 39 92
147 220 123 103 148 130 212 231 247 161 133 212 243 223 67 60
93 109 89  5 79 124 172 18 167 69 208 204 241 234 230 178
151 242 147 236 235 164 40 69 47 107 11 86 42 189 41 237
116 229 229 33 56 241 235 164 199 185 201 24 202 76  3 79
232 62 203 68 61 142 109 35 55 61 111 229 83 12 160 166
125 71 187 159 227 185 252 205 75 242 26 119 212 67 238 173
248 240 74 55 146 204 217 120 223 14 12  7 196 49 31 198
81 158 165 91 121 133 17 186 22 213 223 139 32 63 208 227
33 174 106 113 36 146 58 169 124 119 230 163 55 83 206 157
242 254 245 218 61 233 154 92 117 165 149 233 171 42 19 246
178 104 218 196 187 56 39 118 191 108 47 157 59 84 209 188
180 54 124 35 26 157  2 127 13 113 105 58 97 240 245 38
123 90 212 222 32 38 216 91 59 14 186 254 251 141 200 199
51 29 222 59 42 49 121 106 32 166 207 88 96 238 187 126
223 68 82 254 69 22 173 132 40 71 189 151 250 174 61 144
31 78 121 122 242 129 233 158 10 80 198 117 172 143 108 164
217 218 136 246 57 244 212 22 113 250 68 178 236 79 170 90
50 219 31  3 110 155 161 146 10 76 13 47 162 104 210 214
13 70 92 83 107 180 69 18 50 73 119 140 44 222 15 158
187 47 168  5 164 165 34 27 196 43 235 129 81 219 20 178
246 93 207 237 180 157  7 131 50 189 241 135 88 21 220 200
131 17 59 69 86 218 72 222 158 130 204 17 38 238 165 192
171 71 93 251 114 183 253 241 56 69 108 67 125 81 16 223
104 203 162 173 67 83 156 225 36 177 254 222 95 150 234 99
116 171 108 224 102 150 241 237 42 65 228 45 134 132 88 249
98 179 78 175 252 111  6 55 181 116 74 63 86 221 233 116
170 238 156 20 162 130 47 34 157 118 190 110 12 238 240 220
222 43 35 251 110 115  5 131 141 198 175 219 23 54 162 200
156 184 175 89 222 240 96 38 71 107 110 162 199 163 139 201
244 75 18 157 85 168 201 20 160 180 200 59 81 60 204 151
174 173 202 204 78 179 121 146 97 65 40 164 223 23 230 148
22 133 155 182  9 252 31 154 131 220 144 214 26 77 83 76
99 113 111 53 219 57 82 107 84 156 148 82 169 243 218 195
31 177 237 135 140 95 107 147 190  1 54 111 112 28 143 34
85 48 20 56 84 218 33 166 24 222 84 64 208 216 88 230
157 57 120 81 189 52 247 91 27 52 146 225 140 111 197 220
64 221 165 67 130 185 25 255 62 69 114 230 118 178 59 45
79 205 241 18 212 88 135 69 242 170 74 232 103 211 227 181
131 102 178 153 59  8 35 213 162 205 204 133 51 113 125 98
107 208 204 165 229 181 77 202 115 121 129 100 75 251 247 22
47 45 231 120 233 136 97 52 19 247 221 45 29 35 182 133
188 15 223 153 43 250 49 251 186 154 252 164 130  1 91 48
130  1 87 160  3  2  1 23 162 130  1 78  4 130  1 74
110 113 200 125 149 119 227 41 245 83 247 36 32 213 235 175
148 150 169 119 129 240 16 122 225 16 109 227 221 132 213 222
48 137  5 24 65 240 243 126 201 86 67 90 228 94 251 74
10 76 62 53 73 70 79 118 40 199 205 174 55 131 250 234
236 115 67 15 227 250  8 35 221 108 154 144 81 247 202 236
12 131 188 126 33 168 156 174 163 148 164 184 56 111 89 81
242 147 172 33 114 132 201 162 102 26 144 97 151 63 123 61
225 24 126 53 136 191 111 151 13 88 94 195  3 131 90 80
186 97 159 123 51 95  3 204 40 209 176 113 67 174 205 199
54 247 238 76 100 141 113 215 150 125 216 83 254 237 236 56
79 21 222 163 10 94 156 225 41 186 216 217 22 216 44 129
222 22 255 248 147 225 223 190 104 90 183  0 251 80 66 24
129  1  1 76 228 10 56 144 72 85 51 45 55 86 77 124
170 135 106 45 166 214 169 95 87 45 143 107 109 113 132 139
109 24 147 162 119 25 83 225 23 230 243 224 182 168 251 103
45 132 117 41 185 92 171 239 43 211 116 57  5 14 99 167
109 104 251  2 215 254 153 105  2 107 89 111 153  3 173 199
166 253  7 51 96 44 144 51 229 153 169 33 213 218 137 210
 3 211 224 240 208 134 161 71 152 20 49 96  0 33 53 64
158 77 132 57 83 245 200 185 112 187 17 168 80 132 253 162
249 102 129 25 111  8 134 76 210 186))

(defparameter *server-resp-2* 
  #(161 129 198 48 129 195 160  3 10  1  1 162 129 155  4 129 152
96 129 149  6  9 42 134 72 134 247 18  1  2  2  2  0
111 129 133 48 129 130 160  3  2  1  5 161  3  2  1 15
162 118 48 116 160  3  2  1 23 162 109  4 107 160 252 120
 4 118 129 31 117 132 35 221 72 37 206 181 62 228 133 127
66 111 171 49 165 109 226 131 60 49 166 90 158  1 102 199
71 142 54 223 110 159 119 47 207 81 137 49 89 138 221 195
 4 224 48 123 228  1 64 98 143 156 58  8 25 116 44 162
153 157 140 64 197 205 159 27 144 53 205 186 230 151 197 231
72 197 103 156 208 193 191 179 216 41 134 91 47  1 126 197
73 231 59 250 24 107 238 202 163 30  4 28  4  4  5 255
255 255 255 255  0  0  0  0 35 27 250 213 198  0 101 161
205 78 143 178 119 91 251 74))




(defparameter *the-response* #(161 130  5 167 48 130  5 163 160  3 10  1  1 162 130  5 154
 4 130  5 150 96 130  5 146  6  9 42 134 72 134 247 18
 1  2  2  1  0 110 130  5 129 48 130  5 125 160  3  2
 1  5 161  3  2  1 14 162  7  3  5  0 32  0  0  0
163 130  4  7 97 130  4  3 48 130  3 255 160  3  2  1
 5 161 13 27 11 69 88 83 69 81 85 73 46 67 79 77
162 19 48 17 160  3  2  1  1 161 10 48  8 27  6 102
106 97 109 101 115 163 130  3 210 48 130  3 206 160  3  2
 1 23 161  3  2  1  3 162 130  3 192  4 130  3 188  2
10 56 184 209 168 187 104 174 76 33 47 244 102 129 190 20
107 250 223 180 208 21 145 186 133 205 106 230 150 214 44 89
130 20 95 174 194 124 153 220 61 69 171 159  1 137 161 223
124 233 152 57 245 203 191 175 122 224 133 17 22 238 150 39
103 56 70 105 110 76 137 178 202 106 228 153 224  5 51 153
77 225 158 105 135 175 234 39 164 117 194 253 145 134 170 99
145 183 243 89 238 115 196 236 70 165 187 165 231 167 128 144
57 179 87 200 92 91 103 224 254 200 215  7 244 67 175 106
74 123 141 77 12 250 115 174 166 213 119 183 90 131 241 174
100 157 158 192 171 46 81 167 76 32 227 218 45 195 225 104
167 16 67 150 23 225 169 167 25 231 20 114 161 99 219 174
40 53 129 105 243 110 70 34 212 56 238 75 117 159 149 166
182 163 245 198 94 26 141 84 106 233 67 176 27 133 229 154
94 13 66 218 179 28 74 10 218 36 211 63 153 240 170 162
65 23 57 177 167 220 115 143 194 91 31 194 241 106 168 43
173  0 47 153 41 133 63 247 207 86 165 106 45 93 113 172
68 100 59 182 162 51  4 46 230 226 240 239 238 175 239 42
232 228 136 230 171 156 34 55 190 106 215 132  4 70 75 178
187 18 87 173 14 213 130 154 173 88 247 193 151 21 80 182
117 196 149 116 66 233 21 47 83 34 83 29 23 127 20 97
91 143  2 158 22 175 54 150 169 66 231 114 169 222 56 16
110 54 136 17 106 134 79 223 139 209 52 81 179 223 245 63
237 160 203 196 110 103 41 13 210 45 203  7 56 206 252 101
34 16 215 198 207 162 215 137 90 211 48 111 45 238 37 188
168 49 233  9 134 18 156 147 217 158 228 42 48 221 137 248
230 48 130 38 248 97 49 211 183 24 226 138 189 86 70 61
211 61 234  6 61 38 226 240 146 219 215 38 45 211 104 76
241 15 224 27 43 46 20 79 63 177 184 242 73 250 65 107
151 151 166 90 114 47 88 14 138 160 39 120 15 18  5 137
139 65  2 170 84 87  3 196 210 238 42 75 243 44 109 34
180 208 79 36 84 79 116 108 139 223 147 222 213 16 217 113
117 39 228 54 178 82  9 46 197 185 59 50 214 187  0 17
246 154 166 47 208 59 226 51 227 194 170 103 227 162 26 138
45 203 228 242 140 198 225 244 243 141 158 119 14 219 129 77
183 10 124 120 41 72  5 65 207 109  6 247 116 126 210 202
248 186 167 97 230 231 177 135 255 60 188 229 229 247 126 153
241 61 43 214 37 194 10 247 10 111 171 24 209  9 245 195
202 19 247  3 108 178 17 153 40  6 13  6 205 250 95 72
89 35 133 71 51 15 128 141 87 165 14 27  5 49  5 157
158 245 65 112 218 148 116 92 19 119 175 195 220 191 217 190
199 199 229 31 21 160 77 192 128 147 45 219 128 70 116 67
255 83 206  3 210 52 156 224 254 217 93 191 255 156  9 164
92 56 68 57 216 26 134 104 24 189 49 194 201 67 20 224
71 201 37 131 230 255 17 178 208 104 69 188 121  7 12 43
11 46 108 54 134 225 164 156 226 130 16 161 21 227 58 102
156 79 173 80 85 69 218 149 46 210 40 124 217 31 120 74
49 178 241 186 18 65 200 33 63 24 189 19 189 81 193 28
127 215 51 86 235 131 181 183 155 63 10 253 92 111 139 113
42 243 96 194 224 48 74 94 158 252 235 232 171 73 133 130
229 17 80 222 243 115 205 170 124 84 182 178 40 103 31 54
129 158 168 207 89 149 52 180 116 223 224 246 113 26  0 199
247 240 149 37 137 164 150 102 242 245 155 45 50 169 194 126
232 109 10 100 190 203 72 132 163 192 126 147 53 93 201 56
130 19 241 109 62 212 80  1 116 141 83 78 247 236 98 202
147 158 188 75 39 239 19 75 219 178 194 142 17 172 228  2
141 43 43 117  8 92 32 140 129 117 87 225 209 200 94 194
58 152 44 238 144 225 154 129 136 77 156 223 35 55 174 204
161 134 58 203 251 195 98 18 59 146 75 128 195 67  7 37
42 232 156 45 31 35 223 114 177 123 132 71 52 74 86 38
10 110 185 61 20 207 18 10 113 39 111 164 130  1 91 48
130  1 87 160  3  2  1 23 162 130  1 78  4 130  1 74
103 27 203 181 72 32 87 40 46 198 188 220 179 165 84 147
178 117 200 140 210 29  4 158 178 94 80 62 222 15  2 197
141  3 167 86 29 60 109 216 102  9 166 92 70 37 111 107
217 106 30 182 250 70 97 104 86 11 59 245 110 135 253 157
160 50 22 166 23 51 230 239 12 169 159 19 35 164 195 248
83 209 224 37 113 168 206 89 168 66 214 116 52 188 187 67
144 57 212 218 113 57 92 181 14 173 120 184 241 16 239 154
229 182  6  1 126 112 235 13 108 83 85 250 44 223 19 57
 7 62 49 80 52  5 175 143 78 165 245 193 179 14 223 247
 5 105 230 204 222 178 147 250 128 151 90 169 204 186 53 29
14 235 73 240 190 216 248 89 37 31 58 156 121 151 110 197
232 147 234 12 244 138 116 146 146 131 239 66 227 53 26 121
72 112 175 183 127 59 27 160 194 145 17 147 211 204 227 236
144 28 184 140 140 140 137  1 56 240 251 50 100 219  3  1
161 220 202 240 22 249 130 147 98  8 54 133 141 193 95 71
42 154 83 145 114 28 41 19 102 136 79 241 103 116 249 219
214 47 39 240 224 52 205 177 82 248 204 236 188 38 202 85
198 192 247 107 201 158 42 44 156 78 213 142 65 246 162 122
194 146 250 81 139 191 185 247 26 114 61 163 62 223 221 13
208  5 28 138 206 60 201 239 197 198 245 34 97 202  7 121
236 162 22 188 84 70 133  6 184 200))

(defparameter *the-server-response* 
  #(161 129 198 48 129 195 160  3 10  1  1 162 129 155  4 129 152
96 129 149  6  9 42 134 72 134 247 18  1  2  2  2  0
111 129 133 48 129 130 160  3  2  1  5 161  3  2  1 15
162 118 48 116 160  3  2  1 23 162 109  4 107 37 210 97
177 64 83 203 115 62 175 180 113 161 200 142 141 191 165 66
 8 119 111 238 182 44 169 221 48 137 35 241 48 106 124 253
62 109 175 185 200 184 192 45 66 87 30 70 200 102 96 157
19 93 69 138 101 31 104  6 79 244 76 69 254 185 167 134
153 158 188 58 70 174 245 224 133 123 175 30 69 150 223 123
214 187 126 115 171 119 31 203 166 217 32 182 155 153 62 154
203 134 122 146 145 171 81 118 163 30  4 28  4  4  5 255
255 255 255 255  0  0  0  0 75 92 80 27 227 18 47 10
189 248 167 242 180 106 176 101))
