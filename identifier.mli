(** Mavryks common identifiers. *)

module type Base58_identifier = sig
  val prefix : string
  val encode : string -> Raw.base58
  val decode : Raw.base58 -> string
end

module type Base58_hash_identifier = sig
  include Base58_identifier

  val size : int
  val hash_string : string -> string

  val check : Raw.base58 -> unit
  (** Decode the base58-hash in various steps while trying to fail with the most
      precise error message. *)
end

module Block_hash : Base58_hash_identifier

module Chain_id : sig
  include Base58_hash_identifier

  val of_base58_block_hash : Raw.base58 -> Raw.base58
end

module Operation_hash : Base58_hash_identifier
module Script_expr_hash : Base58_hash_identifier
module Protocol_hash : Base58_hash_identifier

module Kt1_address : sig
  include Base58_hash_identifier

  val of_base58_operation_hash : ?index:int32 -> Raw.base58 -> Raw.base58
end

module type Signer = sig
  module Secret_key : Base58_identifier
  module Public_key : Base58_identifier

  module Public_key_hash : sig
    include Base58_hash_identifier
  end

  module Signature : Base58_identifier
end

module Ed25519 : Signer
module Secp256k1 : Signer
module P256 : Signer

module Generic_signer : sig
  val all : (module Signer) list

  module Public_key : sig
    type t

    val of_bytes : bytes -> t
    val of_base58 : Raw.base58 -> t
    val to_base58 : t -> Raw.base58
  end

  module Public_key_hash : sig
    type t

    val of_public_key : Public_key.t -> t
    val to_base58 : t -> string
  end

  module Signature : sig
    type t

    val of_base58 : Raw.base58 -> t
    val to_bytes : t -> string
  end
end

module Address : sig
  type t = Kt1 of string | Pkh of Generic_signer.Public_key_hash.t

  val of_bytes : bytes -> t
  val to_base58 : t -> string
end
