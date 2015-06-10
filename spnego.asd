;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(asdf:defsystem :spnego
  :name "spnego"
  :author "Frank James <frank.a.james@gmail.com>"
  :description "SPNEGO authentication library"
  :license "MIT"
  :components
  ((:file "spnego"))
  :depends-on (:glass :cerberus :ntlm))

