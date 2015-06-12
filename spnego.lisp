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
      (declare (type neg-token-init tok))
      ;; ok, we've got the init neg-token. this contains a list of mechanisms and an optimistic initial token
      ;; if we support one of the mechansims then just try the token directly 
      (let ((first (first (neg-token-init-mech-types tok))))
        ;; if the first one is ntlm or kerberos then we can proceed immediately, otherwise we reject outright
        (cond
          ((and (cerberus::kerberos-oid-p first) 
                (cerberus::oid-eql (spnego-creds-oid creds) cerberus::*kerberos-oid*))
           ;; the token is a kerberos token and the credentials are Kerberos credentials 
           (multiple-value-bind (context buffer) 
	       (glass:accept-security-context (spnego-creds creds) 
					      (neg-token-init-token tok))
             (declare (ignore buffer))
	     ;; fixme: if mutual authentication is required then we send that pack to the client
	     ;; otherwise we are done 
             (values (make-instance 'spnego-server-context 
                                    :creds creds
                                    :context context
                                    :state :completed)
                     nil)))
          ((and (cerberus::oid-eql first *ntlm-oid*)
                (cerberus::oid-eql (spnego-creds-oid creds) *ntlm-oid*))
           ;; is an ntlm token and we are using ntlm 
           (multiple-value-bind (context ntlm-buffer) 
	       (glass:accept-security-context (spnego-creds creds) 
					      (neg-token-init-token tok))
	     ;; the token MUST be a NEGOTIATE ntlm token. we return the CHALLENGE token back to the client
             (values (make-instance 'spnego-server-context 
                                    :creds creds
                                    :context context 
                                    :state :negotiate)
                     (pack #'encode-nego-token
			   (make-neg-token-resp :state :incomplete
						:mech *ntlm-oid*
						:token ntlm-buffer)))))
          (t 
            (error 'glass:gss-error :major :bad-mech)))))))

;; for generating mutual authentication responses
(defmethod glass:accept-security-context ((context spnego-server-context) buffer &key)
  ;; if the context is provided then we are continuing a previously initialized context
  (ecase (spnego-context-state context)
    (:init (error 'glass:gss-error :major :defective-token)) ;;"Context still in initial state"))
    (:negotiate 
     ;; we have already negotiated the supported authentication systems
     ;; the buffer is expected to be a real kerberos token
     (let ((tok (flexi-streams:with-input-from-sequence (s buffer)
                  (decode-nego-token s))))       
       ;; tok should be a neg-token-resp
       (declare (type neg-token-resp tok))

       ;; the mech type MUST be NTLM, Kerberos doesn't need this stage
       (let ((oid (spnego-creds-oid (spnego-context-creds context))))
	 (unless (cerberus::oid-eql *ntlm-oid* oid)
	   (error 'glass:gss-error :major :defective-token))
	 (when (neg-token-resp-mech tok)
	   (unless (cerberus::oid-eql (neg-token-resp-mech tok) *ntlm-oid*)
	     (error 'glass:gss-error :major :defective-token))))

       ;; It's an NTLM token, validate the AUTHENTICATE message 
       (let ((cxt (glass:accept-security-context (spnego-context-cxt context)
                                                 (neg-token-resp-token tok))))
         (values (make-instance 'spnego-server-context 
                                :state :completed
                                :creds (spnego-context-creds context)
                                :context cxt)
                 nil))))
    (:completed (error 'glass:gss-error :major :defective-token))))

 (defmethod glass:context-principal-name ((context spnego-server-context) &key)
   ;; just call the underlying implementation
   (glass:context-principal-name (spnego-context-cxt context)))


