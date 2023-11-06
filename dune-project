(lang dune 2.9)
(generate_opam_files true)
(name mavai-base58-digest)
(package
  (name mavai-base58-digest)
  (authors
    "Seb Mondet <seb@mondet.org>"
    "Mark Nichols <marklnichols@gmail.com>"
    "Phil Saxton <phillipsaxton@gmail.com>"
    "David Turner <david.turner@oxheadalpha.com>"
    "Tristan Allaire <tristan@mavryk.io>"
  )
  (maintainers
    "Seb Mondet <seb@mondet.org>"
    "Mark Nichols <marklnichols@gmail.com>"
    "Phil Saxton <phillipsaxton@gmail.com>"
    "Tristan Allaire <tristan@mavryk.io>"
  )
  (synopsis "Mavryk Base58 hash-encodings based on Digestif")
  (description "Mavryk Base58 hash-encodings, including common prefixes, based on the Digestif library (Js-of-OCaml compliant).")
  (homepage "https://gitlab.com/mavryk-network/mavai-base-58-digest")
  (bug_reports "https://gitlab.com/mavryk-network/mavai-base-58-digest/-/issues")
  (license "MIT")
  (depends
    (digestif (>= "0.9.0"))
    zarith
    (ppx_expect (>= "0.14.0"))
    (ppx_inline_test (>= "0.14.0"))
  )
)
