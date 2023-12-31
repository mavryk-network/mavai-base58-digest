module List = ListLabels
module String = StringLabels

module type Base58_identifier = sig
  val prefix : string
  val encode : string -> Raw.base58
  val decode : Raw.base58 -> string
end

module type Base58_hash_identifier = sig
  include Base58_identifier

  val size : int
  val hash_string : string -> string
  val check : string -> unit
end

module Base58_prefixed (Parameters : sig
  val prefix : string
end) =
struct
  include Parameters

  let encode s = Raw.String.to_base58 (prefix ^ s)

  let decode s =
    let whole = Raw.String.of_base58 s in
    let prelen = String.length prefix in
    if String.equal prefix (String.sub whole ~pos:0 ~len:prelen) then
      String.sub whole ~pos:prelen ~len:(String.length whole - prelen)
    else
      Format.kasprintf failwith "decode: wrong prefix %S Vs %S" prefix
        (String.sub whole ~pos:0 ~len:prelen)
end

module Base58_hash (Parameters : sig
  val prefix : string
  val size : int
end) =
struct
  include Parameters

  module Sized_blacke2b = Digestif.Make_BLAKE2B (struct
    let digest_size = size
  end)

  let hash_string x = Sized_blacke2b.(to_raw_string (digest_string x))

  include Base58_prefixed (Parameters)

  let check hashed_string =
    let optry ~f k =
      Format.kasprintf
        (fun message ->
          match f () with
          | Some _ -> ()
          | None -> Format.kasprintf failwith "%s" message
          | exception Failure msg ->
              Format.kasprintf failwith "%s (Failure: %s)" message msg
          | exception e ->
              Format.kasprintf failwith "%s (Exception: %s)" message
                (Printexc.to_string e))
        k
    in
    let exntry ~f k = optry ~f:(fun () -> Some (f ())) k in
    let bitcoin_alphabet = Vbmithr_base58.Alphabet.(all_characters default) in
    String.iteri hashed_string ~f:(fun idx c ->
        optry
          ~f:(fun () -> String.index_opt bitcoin_alphabet c)
          "Character %c (0x%x) at index %d is not part the Base58 alphabet." c
          (Char.code c) idx);
    exntry
      ~f:(fun () ->
        let whole = Raw.String.of_base58 hashed_string in
        let prelen = String.length prefix in
        let pref = String.sub whole ~pos:0 ~len:prelen in
        if String.equal pref prefix then ()
        else Format.kasprintf failwith "Wrong prefix: %S" pref;
        let decoded = decode hashed_string in
        let _ = Sized_blacke2b.of_raw_string decoded in
        ())
      "Cannot decode base58 from %S" hashed_string;
    ()
end

module Block_hash = struct
  include Base58_hash (struct
    let prefix = Prefix.block_hash
    let size = 32
  end)
end

module Chain_id = struct
  include Base58_hash (struct
    let prefix = Prefix.chain_id
    let size = 4
  end)

  let of_base58_block_hash hash =
    let of_block_hash block_hash =
      String.sub (Crypto_hash.String.blake2b ~size:32 block_hash) ~pos:0 ~len:4
    in
    encode (of_block_hash (Block_hash.decode hash))

  let%test _ =
    let flextesas_ones =
      (* Cf. Flextesa's vanity chain-ids in src/lib/interactive_mini_network.ml *)
      [
        ( "BLmtDwmAm1FS1Ak5E2UN5Qu7MGnbpzonCqDUfSj4iC8AT5fteWa",
          "NetXyJVJ3mkBox6" );
        ( "BLkENGLbHJ6ZL9vX7Kabb33yHsWL2z8bKzFFS3ntwTzz91YiTYb",
          "NetXMFJWfpUBox7" );
        ( "BKverc3LnaRdiXUe9ruHrKqejFB3t9ZXxrqeH1Cwtfnbf9HhJtk",
          "NetXnuwTfg9Box8" );
        ( "BMJqwuTLa3aSi3KAg4XtvSdVe5r7RuoXh5n15DwEoivx2Ve3Wfk",
          "NetXfpUfwJdBox9" );
        ( "BLCRemfAUthe9XSXuJmuH5PmwvQk55aZUwtCbGZdjLh2niWZSJZ",
          "NetXzcB5DmnBoxG" );
        ( "BLzMUYbk7sD6QG2H7tzLaJyU6dcN6ySE6dkVms49pY72DPN4Tfa",
          "NetXgbFy27eBoxH" );
      ]
    in
    let test_flextesa (block, chain_id) =
      Printf.eprintf "Trying of_base58_block_hash %s = %S Vs %s\n" block
        (of_base58_block_hash block)
        chain_id;
      of_base58_block_hash block = chain_id
    in
    List.for_all ~f:test_flextesa flextesas_ones

  let%expect_test _ =
    let open Printf in
    let print_check s =
      try
        check s;
        printf "OK\n%!"
      with
      | Failure msg -> printf "KO: %s\n%!" msg
      | e -> printf "KO: %s\n%!" (Printexc.to_string e)
    in
    print_check "PsIthaca";
    [%expect
      {| KO: Character I (0x49) at index 2 is not part the Base58 alphabet. |}];
    print_check "Psithaca";
    [%expect
      {|
        KO: Cannot decode base58 from "Psithaca" (Exception: Invalid_argument("Base58.of_string_exn")) |}];
    print_check "PsiThaCaT47Zboaw71QWScM8sXeMM7bbQFncK9FLqYc6EKdpjVP";
    [%expect
      {|
        KO: Cannot decode base58 from "PsiThaCaT47Zboaw71QWScM8sXeMM7bbQFncK9FLqYc6EKdpjVP" (Failure: Wrong prefix: "\002\170\131") |}];
    print_check "NetXgbFy27eBoxH";
    [%expect {| OK |}];
    ()
end

module Operation_hash = struct
  include Base58_hash (struct
    let prefix = Prefix.operation_hash
    let size = 32
  end)
end

module Kt1_address = struct
  include Base58_hash (struct
    let prefix = Prefix.contract_hash
    let size = 20
  end)

  let of_base58_operation_hash ?(index = 0l) op_hash =
    let operation_hash_bytes = Operation_hash.decode op_hash in
    let to_hash =
      let buf = Buffer.create (String.length operation_hash_bytes + 4) in
      Buffer.add_string buf operation_hash_bytes;
      Buffer.add_int32_be buf index;
      Buffer.contents buf
    in
    encode (Crypto_hash.String.blake2b ~size to_hash)

  let%test _ =
    let expected =
      (* See https://gist.github.com/smondet/006fa072e8d7afb32ba1adec106b09d8 *)
      [
        ( "ooLC2QykF5NGiugdTyXJwsn2MEPMdRYJ4TeUoPMx8s38NzFximC",
          0x0l,
          "KT1B94zMXzBr5nLuGXxx1GF7r6uSK6Sfz7pn" );
        ( "opCCqC2xtPgXHdoYynQF4WajE3BvAJwr2uJN4jS54ziweKCiUgw",
          0x0l,
          "KT1BUd1YiPewuhYtbRpJqjrQj2yW55u1vEQB" );
        ( "opCCqC2xtPgXHdoYynQF4WajE3BvAJwr2uJN4jS54ziweKCiUgw",
          0x1l,
          "KT1VRpdD6jhMDdtR2QSLbRYDyFMkZpudVMAP" );
        ( "opCCqC2xtPgXHdoYynQF4WajE3BvAJwr2uJN4jS54ziweKCiUgw",
          0x3ffl,
          "KT1B49o4pF1wfv562fHcZ1wCzGFp8JdFkHeN" );
        ( "opCCqC2xtPgXHdoYynQF4WajE3BvAJwr2uJN4jS54ziweKCiUgw",
          0xdeadbeefl,
          "KT1EiKdPhuxRXrk9WtGEPVNp8aLYXFzJ1FGZ" );
      ]
    in
    List.for_all expected ~f:(fun (op, index, expected_kt1) ->
        let computed = of_base58_operation_hash op ~index in
        Printf.eprintf
          "Trying of_base58_operation_hash %s ~index:%ld = %S Vs %s\n" op index
          computed expected_kt1;
        computed = expected_kt1)
end

module Script_expr_hash = struct
  include Base58_hash (struct
    let prefix = Prefix.script_expr_hash
    let size = 32
  end)
end

module Protocol_hash = struct
  include Base58_hash (struct
    let prefix = Prefix.protocol_hash
    let size = 32
  end)
end

module type Signer = sig
  module Secret_key : Base58_identifier
  module Public_key : Base58_identifier

  module Public_key_hash : sig
    include Base58_hash_identifier
  end

  module Signature : Base58_identifier
end

module Ed25519 = struct
  module Secret_key = struct
    include Base58_prefixed (struct
      let prefix = Prefix.ed25519_seed
    end)
  end

  module Public_key = struct
    include Base58_prefixed (struct
      let prefix = Prefix.ed25519_public_key
    end)
  end

  module Public_key_hash = struct
    include Base58_hash (struct
      let prefix = Prefix.ed25519_public_key_hash
      let size = 20
    end)
  end

  module Signature = struct
    include Base58_prefixed (struct
      let prefix = Prefix.ed25519_signature
    end)
  end
end

module Secp256k1 = struct
  module Secret_key = struct
    include Base58_prefixed (struct
      let prefix = Prefix.secp256k1_secret_key
    end)
  end

  module Public_key = struct
    include Base58_prefixed (struct
      let prefix = Prefix.secp256k1_public_key
    end)
  end

  module Public_key_hash = struct
    include Base58_hash (struct
      let prefix = Prefix.secp256k1_public_key_hash
      let size = 20
    end)
  end

  module Signature = struct
    include Base58_prefixed (struct
      let prefix = Prefix.secp256k1_signature
    end)
  end

  let%expect_test _ =
    let open Printf in
    let module M = struct
      module type Codec = sig
        val encode : string -> string
        val decode : string -> string
      end
    end in
    let print_check_0 (module C : M.Codec) s =
      let d = C.decode s in
      let e = C.encode d in
      assert (String.equal s e);
      printf "->%S\n->%s\n" d e
    in
    print_check_0
      (module Public_key_hash)
      "mv2e64pXo4SE1j574ufcRTvQkfdio3aHvWeV";
    [%expect
      {|
        ->"\198(\"!\246a\003:\004\156\029D\179\202\025\240\247\192;\149"
        ->mv2e64pXo4SE1j574ufcRTvQkfdio3aHvWeV |}];
    print_check_0
      (module Public_key)
      "sppk7asaMpcW2Sqo4iftKn5bXYcsqyJ9CktTuqPss2oCWkbB9QHTrjR";
    [%expect
      {|
        ->"\002\206}bP\180\226\206\173\004\146\023I\202\186\r\154\0007\160V\004\198\161\162U\016\136\242\225\006\2455"
        ->sppk7asaMpcW2Sqo4iftKn5bXYcsqyJ9CktTuqPss2oCWkbB9QHTrjR |}];
    print_check_0
      (module Secret_key)
      "spsk1qg2jd5SBa2TyiUT3jERCD95bdSuuhJAt75ZYrzRC1VnWb3tg7";
    [%expect
      {|
        ->"6\190V>,\205$\203\128-p\"\138\197M4w\2177\161*\219\017O\227\255\243\134\165\007\211\232"
        ->spsk1qg2jd5SBa2TyiUT3jERCD95bdSuuhJAt75ZYrzRC1VnWb3tg7 |}];
    ()
end

module P256 = struct
  module Secret_key = struct
    include Base58_prefixed (struct
      let prefix = Prefix.p256_secret_key
    end)
  end

  module Public_key = struct
    include Base58_prefixed (struct
      let prefix = Prefix.p256_public_key
    end)
  end

  module Public_key_hash = struct
    include Base58_hash (struct
      let prefix = Prefix.p256_public_key_hash
      let size = 20
    end)
  end

  module Signature = struct
    include Base58_prefixed (struct
      let prefix = Prefix.p256_signature
    end)
  end

  let%expect_test _ =
    let open Printf in
    let module M = struct
      module type Codec = sig
        val encode : string -> string
        val decode : string -> string
      end
    end in
    let print_check_0 (module C : M.Codec) s =
      let d = C.decode s in
      let e = C.encode d in
      assert (String.equal s e);
      printf "->%S\n->%s\n" d e
    in
    print_check_0
      (module Public_key_hash)
      "mv3BWRYh1y2tWHDhgQFJHoEwVYwey42c5mME";
    [%expect
      {|
        ->"\030\207QP\192\163\200J\\\157EE\157\144M\170(\164e\161"
        ->mv3BWRYh1y2tWHDhgQFJHoEwVYwey42c5mME |}];
    print_check_0
      (module Public_key)
      "p2pk67zrpWCT1ihu7zyG7p89UN6w8MkYN9mZ8nMZexf6WPVFXQz3BGP";
    [%expect
      {|
        ->"\003\195*\135\135:\001\019\020`0\129\233op\224J\019\168r\139:\231\220\215\0266\133\183\1987F\029"
        ->p2pk67zrpWCT1ihu7zyG7p89UN6w8MkYN9mZ8nMZexf6WPVFXQz3BGP |}];
    print_check_0
      (module Secret_key)
      "p2sk2PGjcuzCndQ5WavEB42Mxt2eagzrfivs5vXxycHFNzkobDygcA";
    [%expect
      {|
        ->"\005\162xK\183\236\247\145\175'/\176,\191V|A\152\149H\234\235%\167\169\219Zj\rd'\160"
        ->p2sk2PGjcuzCndQ5WavEB42Mxt2eagzrfivs5vXxycHFNzkobDygcA |}];
    ()
end

module Generic_signer = struct
  type 'a t = (module Signer) * 'a

  let all : (module Signer) list =
    [ (module Ed25519); (module Secp256k1); (module P256) ]

  module Public_key = struct
    type nonrec t = string t

    let of_bytes s : t =
      let lgth = Bytes.length s in
      let check_lgth n =
        if lgth <> n then
          Format.kasprintf failwith
            "Public_key.of_bytes: length must be %d bytes, not %d." n lgth
      in
      let chop s = Bytes.sub_string s 1 (lgth - 1) in
      match Bytes.get s 0 with
      | '\x00' ->
          check_lgth 33;
          ((module Ed25519), chop s)
      | '\x01' ->
          check_lgth 34;
          ((module Secp256k1), chop s)
      | '\x02' ->
          check_lgth 34;
          ((module P256), chop s)
      | c ->
          Format.kasprintf failwith "public key magic number not recognized: %C"
            c

    let of_base58 (s : Raw.base58) : t =
      List.find_map all ~f:(fun (module Sg : Signer) ->
          match Sg.Public_key.decode s with
          | s -> Some ((module Sg : Signer), s)
          | exception _ -> None)
      |> function
      | Some s -> s
      | None ->
          Format.kasprintf failwith "Public_key.of_base58: could not decode %S"
            s

    let to_base58 (((module Sg), pk) : t) : Raw.base58 = Sg.Public_key.encode pk

    let%expect_test _ =
      let open Printf in
      let bytes_of_hex s =
        let rec go b = function
          | "" -> Buffer.to_bytes b
          | more ->
              Scanf.sscanf more "%02x%s" (fun code more ->
                  Buffer.add_int8 b code;
                  go b more)
        in
        go (Buffer.create 40) s
      in
      let print_check_0 hex =
        let e = to_base58 (of_bytes (bytes_of_hex hex)) in
        printf "->0x%s\n->%s\n" hex e
      in
      print_check_0
        "00d670f72efd9475b62275fae773eb5f5eb1fea4f2a0880e6d21983273bf95a0af";
      [%expect
        {|
        ->0x00d670f72efd9475b62275fae773eb5f5eb1fea4f2a0880e6d21983273bf95a0af
        ->edpkvGfYw3LyB1UcCahKQk4rF2tvbMUk8GFiTuMjL75uGXrpvKXhjn |}];
      print_check_0
        "010227ad543e5213d44e3e1595e5c43e308a05a1c9f816d1a870631a43418d606159";
      [%expect
        {|
        ->0x010227ad543e5213d44e3e1595e5c43e308a05a1c9f816d1a870631a43418d606159
        ->sppk7Zc7MRN3zTXEZ5QVp7yWcM2YhVyRUQqfBhxA25Ebxz3wbiuA1qa |}];
      print_check_0
        "02022ca01ff53a224ced334a41979f96b97c307f951ffdea36433ee24b5fc6a9588e";
      [%expect
        {|
        ->0x02022ca01ff53a224ced334a41979f96b97c307f951ffdea36433ee24b5fc6a9588e
        ->p2pk64upHUAeH6wNh5BgwTrnVVM6aU9zbSdmgoeDVkax46d8T4C7MsC |}];
      ()
  end

  module Public_key_hash = struct
    type nonrec t = string t

    let of_public_key (((module Sg), pk) : Public_key.t) : t =
      ((module Sg : Signer), Sg.Public_key_hash.hash_string pk)

    let to_base58 (((module Sg), pkh) : t) : Raw.base58 =
      Sg.Public_key_hash.encode pkh
  end

  module Signature = struct
    type nonrec t = string t

    let of_base58 (s : Raw.base58) : t =
      List.find_map all ~f:(fun (module Sg : Signer) ->
          match Sg.Signature.decode s with
          | s -> Some ((module Sg : Signer), s)
          | exception _ -> None)
      |> function
      | Some s -> s
      | None ->
          Format.kasprintf failwith "Signature.of_base58: could not decode %S" s

    let to_bytes : t -> string = fun (_, s) -> s
  end
end

module Address = struct
  type t = Kt1 of string | Pkh of Generic_signer.Public_key_hash.t

  let of_bytes s : t =
    (* See ["./mavryk-codec describe alpha.contract binary schema"] *)
    let lgth = Bytes.length s in
    match Bytes.get s 0 with
    | '\x01' when lgth = 22 ->
        Kt1 (Bytes.sub_string s 1 (lgth - 2) (* <- the padding is at the end *))
    | '\x00' when lgth = 22 -> (
        let chop s = Bytes.sub_string s 2 (Bytes.length s - 2) in
        match Bytes.get s 1 with
        | '\x00' -> Pkh ((module Ed25519), chop s)
        | '\x01' -> Pkh ((module Secp256k1), chop s)
        | '\x02' -> Pkh ((module P256), chop s)
        | _ ->
            Format.kasprintf failwith
              "Address/TZ 2nd magic number not recognized: %S"
              (Bytes.to_string s))
    | _ when lgth = 22 ->
        Format.kasprintf failwith "Address 1st magic number not recognized: %S"
          (Bytes.to_string s)
    | _ ->
        Format.kasprintf failwith "Address length not recognized: %S (%d)"
          (Bytes.to_string s) lgth

  let to_base58 = function
    | Kt1 s -> Kt1_address.encode s
    | Pkh pkh -> Generic_signer.Public_key_hash.to_base58 pkh

  let%expect_test _ =
    let open Printf in
    let bytes_of_hex s =
      let rec go b = function
        | "" -> Buffer.to_bytes b
        | more ->
            Scanf.sscanf more "%02x%s" (fun code more ->
                Buffer.add_int8 b code;
                go b more)
      in
      go (Buffer.create 40) s
    in
    let print_check_0 hex =
      let e = to_base58 (of_bytes (bytes_of_hex hex)) in
      printf "->0x%s\n->%s\n" hex e
    in
    print_check_0 "00006ca63af795024a42b1b1875b24c2fc7f4376b23c";
    [%expect
      {|
        ->0x00006ca63af795024a42b1b1875b24c2fc7f4376b23c
        ->tz1VYWoiunmeTe2CN7LZigbERFfekrtymKoy |}];
    print_check_0 "0001c6282221f661033a049c1d44b3ca19f0f7c03b95";
    [%expect
      {|
        ->0x0001c6282221f661033a049c1d44b3ca19f0f7c03b95
        ->mv2e64pXo4SE1j574ufcRTvQkfdio3aHvWeV |}];
    print_check_0 "0002798a0ad8e4956c6afba177f19ae41b6b169a6145";
    [%expect
      {|
        ->0x0002798a0ad8e4956c6afba177f19ae41b6b169a6145
        ->tz3XQgkE3jTFP9RhadxKHW6LZmiGqiN95uWy |}];
    print_check_0 "01bc547d8187e0bc39ea403195ebb3cd1ef5a1849d00";
    [%expect
      {|
        ->0x01bc547d8187e0bc39ea403195ebb3cd1ef5a1849d00
        ->KT1RkZpKFkwjWTRL4Vyqnwpzh83q6ipi6zvT |}];
    ()
end
