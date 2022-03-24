(lang dune 2.9)
(generate_opam_files true)
(name tezai-base58-digest)
(package
  (name tezai-base58-digest)
  (authors
    "Seb Mondet <seb@mondet.org>"
    "Mark Nichols <marklnichols@gmail.com>"
    "Phil Saxton <phillipsaxton@gmail.com>"
    "David Turner <david.turner@oxheadalpha.com>"
  )
  (maintainers
    "Seb Mondet <seb@mondet.org>"
    "Mark Nichols <marklnichols@gmail.com>"
    "Phil Saxton <phillipsaxton@gmail.com>"
  )
  (synopsis "Tezos Base58 hash-encodings based on Digestif")
  (description "Tezos Base58 hash-encodings, including common prefixes, based on the Digestif library (Js-of-OCaml compliant).")
  (homepage "https://gitlab.com/oxheadalpha/tezai-base58-digest")
  (bug_reports "https://gitlab.com/oxheadalpha/tezai-base58-digest/-/issues")
  (license "MIT")
  (depends
    (digestif (>= "0.9.0"))
    (ppx_expect (>= "0.14.0"))
    (ppx_inline_test (>= "0.14.0"))
  )
)
