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
  (flags cerberus::kerberos-flags :tag 1 :optional t)
  (token cerberus::asn1-octet-string :tag 2 :optional t)
  (mic cerberus::asn1-octet-string :tag 3 :optional t))


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


;; GSS Api

(defclass spnego-credentials ()
  ((krb-creds :initarg :creds :reader spnego-creds)))

(defmethod glass:acquire-credentials ((type (eql :spnego)) principal &key)
  ;; just return the kerberos crfeds
  (make-instance 'spnego-credentials
                 :creds (glass:acquire-credentials :kerberos principal)))


(defclass spnego-context ()
  ((creds :initarg :creds :reader spnego-context-creds)
   (state :initform :init :accessor spnego-context-state)
   (context :initarg :context :initform nil :reader spnego-context-cxt)))

;; state can be:
;; :init ::= initial state (nothing done yet)
;; :negotiate ::= client has sent an initial negotiate token, server has received the negotiate token
;; :complete ::= client has sent a real token, server has received the real token

(defclass spnego-client-context (spnego-context)
  ())

(defmethod glass:initialize-security-context ((creds spnego-credentials) &key)
  ;; no input buffer supplied, this is an initial negotiation request 
  ;; generate and pack an init token, wrapped with the spnego oid
  (let ((buffer 
         (flexi-streams:with-output-to-sequence (s)
           (encode-initial-context-token s 
                                         (pack #'encode-nego-token 
                                               (make-neg-token-init :mech-types (list cerberus::*kerberos-oid*)
                                                                    :flags nil))))))
    (values (make-instance 'spnego-client-context 
                           :creds creds
                           :state :negotiate)
            buffer)))


(defmethod glass:initialize-security-context ((cxt spnego-client-context) &key buffer)
  ;; a buffer is supplied, this means it is a second round of processing
  ;; the buffer should be a nego-token-resp buffer 
  (let ((tok (flexi-streams:with-input-from-sequence (s buffer)
               (decode-nego-token s))))
    (declare (type neg-token-resp tok))
    ;; ensure that kerberos is a supported mech
    (unless (cerberus::kerberos-oid-p (neg-token-resp-mech tok))
      (error "Neg token mech ~S not Kerberos OID" (neg-token-resp-mech tok)))
    (multiple-value-bind (krb-context resp-buff) 
        (glass:initialize-security-context (spnego-creds (spnego-context-creds cxt)))
      (values (make-instance 'spnego-client-context 
                             :creds (spnego-context-creds cxt)
                             :state :complete
                             :context krb-context)
              (flexi-streams:with-output-to-sequence (s)
                (encode-nego-token s 
                                   (make-neg-token-resp :state :complete
                                                        :mech cerberus::*kerberos-oid*
                                                        :token resp-buff
                                                        :mic nil)))))))

(defclass spnego-server-context (spnego-context)
  ())

(defmethod glass:accept-security-context ((context spnego-server-context) buffer &key)
  ;; if the context is provided then we are continuing a previously initialized context
  (ecase (spnego-context-state context)
    (:init (error "Context still in initial state"))
    (:negotiate 
     ;; we have already negotiated the supported authentication systems
     ;; the buffer is expected to be a real kerberos token
     (let ((tok (flexi-streams:with-input-from-sequence (s buffer)
                  (decode-nego-token s))))
       ;; tok should be a neg-token-resp
       (declare (type neg-token-resp tok))
       ;; assume it's a kerberos token and pass to cerberus
       (let ((cxt (glass:accept-security-context (spnego-creds (spnego-context-creds context)) 
                                                 (neg-token-resp-token tok))))
         (values (make-instance 'spnego-server-context 
                                :state :complete
                                :creds (spnego-context-creds context)
                                :context cxt)
                 nil))))
    (:complete (error "Context completed"))))

(defmethod glass:accept-security-context ((creds spnego-credentials) buffer &key)
     (let ((msg (flexi-streams:with-input-from-sequence (s buffer)
                  (decode-initial-context-token s))))
       (let ((tok (flexi-streams:with-input-from-sequence (s msg)
                    (decode-nego-token s))))
         (values (make-instance 'spnego-server-context 
                                :creds creds
                                :state :negotiate)
                 tok))))


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

      

