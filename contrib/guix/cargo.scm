(use-modules (gnu packages)
             (gnu packages bash)
             ((gnu packages certs) #:select (nss-certs))
             (gnu packages rust)
             (gnu packages wget)
             (gnu packages compression)
             ((gnu packages version-control) #:select (git-minimal))
             ((gnu packages tls) #:select (openssl)))

(packages->manifest
  (append
    (list
      bash
      coreutils-minimal
      nss-certs
      openssl
      rust
      git-minimal
      wget
      tar
      gzip
      (list rust "cargo"))))