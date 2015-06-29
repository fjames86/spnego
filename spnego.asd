;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(asdf:defsystem :spnego
  :name "spnego"
  :author "Frank James <frank.a.james@gmail.com>"
  :description "Provides SPNEGO (Negotiate) authentication system to the glass API."
  :license "MIT"
  :version "1.0.1"
  :components
  ((:file "spnego"))
  :depends-on (:glass :cerberus :ntlm))


