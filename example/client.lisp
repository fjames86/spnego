;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

;;; This shows how you might write an HTTP client that does SPEGNO authentication,
;;; it's almost exactly the same as the equivalent eample for NTLM.
;;; You need drakma and cl-base64 systems.
;;; Try pointing the client at the HTTP server provided by server.c. 

(defpackage #:spnego.example
  (:use #:cl))

(in-package #:spnego.example)

;; before running this you must first set things up by calling either
;; (cerberus:logon-user "username" "password" "domain")
;; (ntlm:logon-user "username" "password" "domain")

(defun send-negotiate-http-request (principal &optional (url "http://localhost:2001/"))
  (let ((creds (gss:acquire-credentials :spnego principal)))
    (multiple-value-bind (init-context buffer) (gss:initialize-security-context creds)
      ;; start by sending a regular request 
      (format t "FIRST ATTEMPT~%")
;;      (format t "~S~%"
;;              (cerberus::unpack-initial-context-token
;;               (spnego::neg-token-init-token 
;;                (spnego::unpack #'spnego::decode-nego-token
;;                                (spnego::unpack #'spnego::decode-initial-context-token buffeR)))
                              
      (multiple-value-bind (content status-code headers ruri stream must-close reason)
          (drakma:http-request url
                               :additional-headers 
                               `((:authorization . ,(format nil 
                                                            "Negotiate ~A" 
                                                            (cl-base64:usb8-array-to-base64-string buffer))))
                               :keep-alive t 
                               :close nil)
        (declare (ignore ruri must-close))
        (case status-code
          (200 (format t "SUCCESS~%")
               (format t "CONTENT:~%")
               (format t "~S~%" content))
          (401 (format t "INITIAL UNAUTHORIZED ~A ~A~%~%" status-code reason)
               ;; extract the WWW-AUTHENTICATE header
               (let ((www (cdr (assoc :www-authenticate headers))))
                 (unless www (error "No WWW-AUTHENTICATE header"))
                 ;; get the buffer from the base64 encoded string 
                 (let ((matches (nth-value 1 (cl-ppcre:scan-to-strings "Negotiate ([\\w=\\+/]+)" www))))
                   (unless matches (error "Not a Negotiate header"))
                   (format t "WWW-AUTHENTICATE~%") ;;: ~A~%" (elt matches 0))
;;                   (format t "~S~%" (cl-base64:base64-string-to-usb8-array (elt matches 0)))
;;                   (handler-case 
;;                       (format t "~S~%" 
;;                               (cerberus::unpack-initial-context-token 
;;                               (spnego::neg-token-resp-token 
;;                                (spnego::unpack #'spnego::decode-nego-token 
;;                                                (cl-base64:base64-string-to-usb8-array (elt matches 0))))
;;                     (error (e) (format t "~A~%" e)))
;;                   (format t "~%")
                   (multiple-value-bind (context buffer)                        
                       (gss:initialize-security-context init-context
                                                        :buffer 
                                                        (cl-base64:base64-string-to-usb8-array (elt matches 0)))
                     (declare (ignore context))
;;                     (format t "~%SECOND ATTEMPT~%")
;;                     (format t "~S~%" buffer)
;;                     (format t "~S~%" (spnego::unpack #'spnego::decode-nego-token buffer))
                     (multiple-value-bind (content status-code headers ruri stream must-close reason)
                         (drakma:http-request url
                                              :additional-headers 
                                              `((:authorization . ,(format nil "Negotiate ~A"
                                                                           (cl-base64:usb8-array-to-base64-string buffer))))
                                              :stream stream)
                       (declare (ignore must-close ruri stream headers))
                       (case status-code 
                         (200 (format t "SUCCESS~%")
                              (format t "CONTENT: ~%")
                              (format t "~S~%" content))
                         (otherwise (format t "FAILED ~A ~A~%" status-code reason))))))))
          (otherwise (format t "FAILED ~A: ~A~%" status-code reason)))))))




