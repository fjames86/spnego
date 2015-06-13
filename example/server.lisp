;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

;;; This shows how you might write an HTTP server that does SPEGNO authentication.
;;; Might not actually work yet.



(defpackage #:spnego.example.server
  (:use #:cl))

(in-package #:spnego.example.server)


(defclass nego-acceptor (hunchentoot:acceptor)
  ((conns :initform nil :accessor acceptor-conns)
   (cred :initform (glass:acquire-credentials :spnego nil) :reader acceptor-creds))
  (:default-initargs :address nil))

(defmethod hunchentoot:acceptor-dispatch-request ((acc nego-acceptor) req)
  ;; get the authorization header
  (flet ((auth-failed () 
	   (setf (hunchentoot:return-code*) hunchentoot:+http-authorization-required+)
	   (return-from hunchentoot:acceptor-dispatch-request)))
    (let ((header (cdr (assoc :authorization (hunchentoot:headers-in*)))))
      (unless header (auth-failed))
      ;; get the negotiate base64 value
      (let ((matches (nth-value 1 (cl-ppcre:scan-to-strings "Negotiate ([\\w=\\+/]+)" header))))
	(unless matches (auth-failed))
	(let ((buffer (cl-base64:base64-string-to-usb8-array (elt matches 0))))
	  (multiple-value-bind (context buffer continue-needed)
	      	  (handler-case (glass:accept-security-context (acceptor-creds acc) buffer)
		    (error () (auth-failed)))
	    (declare (ignore context))
	    (cond
	      (continue-needed 
	       (setf (hunchentoot:return-code*) hunchentoot:+http-authorization-required+)
	       (setf (hunchentoot:header-out :www-authenticate)
		     (format nil "Negotiate ~A" (cl-base64:usb8-array-to-base64-string buffer)))
	       (return-from hunchentoot:acceptor-dispatch-request))
	      (t 
	       ;; authorized
	       (setf (hunchentoot:return-code*) hunchentoot:+http-ok+)
	       "Authorized!!!"))))))))


(defvar *acceptor* nil)

(defun start-test-server (port)
  (setf *acceptor* (make-instance 'nego-acceptor :port port))
  (hunchentoot:start *acceptor*))

(defun stop-test-server ()
  (hunchentoot:stop *acceptor*)
  (setf *acceptor* nil))
