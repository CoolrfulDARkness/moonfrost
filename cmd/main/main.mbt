///|
/// MoonFROST End-to-End Interactive Demonstration CLI
/// Pure MoonBit · Zero-FFI · Constant-Time · IETF RFC 9591 FROST Threshold Schnorr
///
/// Run on any target with:
///   moon run cmd/main --target wasm
///   moon run cmd/main --target js
///   moon run cmd/main --target native

///|
fn[T] expect_frost(res : Result[T, @frost.FrostError], ctx : String) -> T {
  match res {
    Ok(v) => v
    Err(e) => abort("FATAL [\{ctx}]: \{e}")
  }
}

///|
fn[T] expect_str(res : Result[T, String], ctx : String) -> T {
  match res {
    Ok(v) => v
    Err(e) => abort("FATAL [\{ctx}]: \{e}")
  }
}

///|
fn[S, E] hex_element(ops : @frost.SuiteOps[S, E], elem : E) -> String {
  @crypto.bytes_to_hex(
    expect_str((ops.serialize_element)(elem), "serialize_element"),
  )
}

///|
fn[S, E] hex_scalar(ops : @frost.SuiteOps[S, E], scalar : S) -> String {
  @crypto.bytes_to_hex((ops.serialize_scalar)(scalar))
}

///|
fn format_quorum(ids : Array[Int32], prefix : String) -> String {
  let buf = StringBuilder()
  buf.write_string("{")
  for i = 0; i < ids.length(); i = i + 1 {
    if i > 0 {
      buf.write_string(", ")
    }
    buf.write_string("\{prefix}\{ids[i]}")
  }
  buf.write_string("}")
  buf.to_string()
}

///|
fn format_id_list(ids : Array[Int32]) -> String {
  let buf = StringBuilder()
  buf.write_string("[")
  for i = 0; i < ids.length(); i = i + 1 {
    if i > 0 {
      buf.write_string(", ")
    }
    buf.write_string("\{ids[i]}")
  }
  buf.write_string("]")
  buf.to_string()
}

///|
fn print_section_header(title : String, subtitle : String) -> Unit {
  println("")
  println(
    "==============================================================================",
  )
  println("  \{title}")
  println("  \{subtitle}")
  println(
    "==============================================================================",
  )
}

///|
fn print_step_header(step : String) -> Unit {
  println("")
  println(
    "------------------------------------------------------------------------------",
  )
  println("  \{step}")
  println(
    "------------------------------------------------------------------------------",
  )
}

///|
/// Runs a complete decentralized 3-round Pedersen DKG for `max_signers` nodes
/// with threshold `min_signers` (no trusted dealer), verifies all nodes agree
/// on the exact same group public key `PK`, and returns `(key_packages, pub_pkg)`.
fn[S, E] run_pedersen_dkg(
  ops : @frost.SuiteOps[S, E],
  max_signers : Int32,
  min_signers : Int32,
  seed_prefix : String,
  node_prefix : String,
) -> (Array[@frost.KeyPackage[S, E]], @frost.PublicKeyPackage[E]) {
  // Round 1: each node samples a secret polynomial, commits with Feldman VSS, and proves PoK of a_0.
  let r1_secrets : Array[@frost.DkgRound1Secret[S]] = []
  let r1_packages : Array[@frost.DkgRound1Package[S, E]] = []
  for id = 1; id <= max_signers; id = id + 1 {
    let drbg = @moonfrost.drbg_from_seed(
      @crypto.ascii_bytes("\{seed_prefix}-dkg-r1-node-\{id}"),
    )
    let (sec, pkg) = expect_frost(
      @moonfrost.dkg_part1(ops, id, max_signers, min_signers, drbg),
      "dkg_part1(\{id})",
    )
    r1_secrets.push(sec)
    r1_packages.push(pkg)
  }
  println(
    "  [DKG Round 1] \{max_signers} 节点完成秘密多项式承诺与 Schnorr PoK 广播 (t=\{min_signers}, n=\{max_signers})",
  )

  // Round 2: each node verifies all Round 1 PoKs and generates private shares f_i(j) for j != i.
  let r2_secrets : Array[@frost.DkgRound2Secret[S, E]] = []
  let r2_sent : Array[Array[@frost.DkgRound2Package[S]]] = []
  for i = 0; i < max_signers; i = i + 1 {
    let (sec2, pkgs2) = expect_frost(
      @moonfrost.dkg_part2(ops, r1_secrets[i], r1_packages),
      "dkg_part2(\{i + 1})",
    )
    r2_secrets.push(sec2)
    r2_sent.push(pkgs2)
  }
  println(
    "  [DKG Round 2] 全部 \{max_signers}x\{max_signers} 个 PoK 验证通过，点对点秘密分片 f_i(j) 分发完成",
  )

  // Round 3: each node verifies all received shares against Feldman VSS commitments and derives PK.
  let key_packages : Array[@frost.KeyPackage[S, E]] = []
  let pub_packages : Array[@frost.PublicKeyPackage[E]] = []
  for idx = 0; idx < max_signers; idx = idx + 1 {
    let receiver_id = idx + 1
    let incoming : Array[@frost.DkgRound2Package[S]] = []
    for sender_idx = 0; sender_idx < max_signers; sender_idx = sender_idx + 1 {
      if sender_idx == idx {
        continue
      }
      let sent_list = r2_sent[sender_idx]
      for k = 0; k < sent_list.length(); k = k + 1 {
        if sent_list[k].receiver == receiver_id {
          incoming.push(sent_list[k])
        }
      }
    }
    let (kp, pub_pkg) = expect_frost(
      @moonfrost.dkg_part3(ops, r2_secrets[idx], r1_packages, incoming),
      "dkg_part3(\{receiver_id})",
    )
    key_packages.push(kp)
    pub_packages.push(pub_pkg)
  }

  // Verify unanimous agreement on group public key PK across all nodes.
  let ref_pk = pub_packages[0].verifying_key
  let ref_pk_bytes = expect_str(
    (ops.serialize_element)(ref_pk),
    "serialize ref group PK",
  )
  let ref_pk_hex = @crypto.bytes_to_hex(ref_pk_bytes)
  for idx = 1; idx < max_signers; idx = idx + 1 {
    let pk_i = pub_packages[idx].verifying_key
    let pk_i_bytes = expect_str(
      (ops.serialize_element)(pk_i),
      "serialize node group PK",
    )
    if !(ops.element_eq)(ref_pk, pk_i) ||
      !@crypto.ct_eq_bytes(ref_pk_bytes, pk_i_bytes) {
      abort("FATAL: DKG group public key mismatch at node \{idx + 1}")
    }
  }
  println(
    "  [DKG Round 3] 全部 \{max_signers} 节点 Feldman VSS 校验通过，无中心达成一致群公钥 PK：",
  )
  println(
    "    Group Public Key PK (\{ref_pk_bytes.length()} bytes): \{ref_pk_hex}",
  )
  for idx = 0; idx < max_signers; idx = idx + 1 {
    let kp = key_packages[idx]
    let vs_hex = hex_element(ops, kp.verifying_share)
    println(
      "    \{node_prefix}\{kp.identifier} Verifying Share PK_\{kp.identifier}: \{vs_hex}",
    )
  }
  println(
    "  [PASS] \{max_signers}/\{max_signers} 节点群公钥 PK 逐字节一致，零可信第三方假设成立！",
  )
  (key_packages, pub_packages[0])
}

///|
/// Runs an honest 2-Round FROST signing session (`commit` -> `sign` -> `aggregate`)
/// with `signer_ids`, verifies canonical signature serialization/deserialization
/// and standard Schnorr `prime_order_verify`, and prints cryptographic artifacts.
fn[S, E] run_honest_signing(
  ops : @frost.SuiteOps[S, E],
  key_packages : Array[@frost.KeyPackage[S, E]],
  pub_pkg : @frost.PublicKeyPackage[E],
  signer_ids : Array[Int32],
  msg_text : String,
  seed_prefix : String,
  node_prefix : String,
) -> (@frost.Signature[S, E], Bytes) {
  let msg = @crypto.ascii_bytes(msg_text)
  println("  Quorum   : \{format_quorum(signer_ids, node_prefix)}")
  println("  Message  : \"\{msg_text}\" (\{msg.length()} bytes)")

  // Round 1: commit
  let nonces_list : Array[@frost.SigningNonces[S, E]] = []
  let commitment_list : Array[@frost.CommitmentEntry[E]] = []
  println(
    "  [Round 1 · commit] 各法定节点生成一次性 Nonce 承诺 (D_i, E_i):",
  )
  for i = 0; i < signer_ids.length(); i = i + 1 {
    let id = signer_ids[i]
    let kp = key_packages[id - 1]
    let drbg = @moonfrost.drbg_from_seed(
      @crypto.ascii_bytes("\{seed_prefix}-r1-node-\{id}"),
    )
    let (nonces, comms) = expect_frost(
      @moonfrost.commit(ops, kp.signing_share, drbg),
      "commit(\{id})",
    )
    println(
      "    \{node_prefix}\{id} D_\{id}: \{hex_element(ops, comms.hiding)}",
    )
    println(
      "    \{node_prefix}\{id} E_\{id}: \{hex_element(ops, comms.binding)}",
    )
    nonces_list.push(nonces)
    commitment_list.push(@frost.CommitmentEntry::new(id, comms))
  }

  // Round 2: sign
  let sig_shares : Array[@frost.SignatureShare[S]] = []
  println(
    "  [Round 2 · sign] 各节点计算绑定因子并产出签名分片 z_i (Nonce 立即清零消费):",
  )
  for i = 0; i < signer_ids.length(); i = i + 1 {
    let id = signer_ids[i]
    let kp = key_packages[id - 1]
    let share = expect_frost(
      @moonfrost.sign(ops, kp, nonces_list[i], msg, commitment_list),
      "sign(\{id})",
    )
    if !nonces_list[i].is_used() {
      abort("FATAL: nonces must be marked used after sign")
    }
    println("    \{node_prefix}\{id} z_\{id}: \{hex_scalar(ops, share.share)}")
    sig_shares.push(share)
  }

  // Coordinator: aggregate + canonical encode + prime_order_verify
  let sig = expect_frost(
    @moonfrost.aggregate(ops, commitment_list, msg, pub_pkg, sig_shares),
    "aggregate",
  )
  let sig_bytes = expect_frost(
    @moonfrost.serialize_signature(ops, sig),
    "serialize_signature",
  )
  let sig_roundtrip = expect_frost(
    @moonfrost.deserialize_signature(ops, sig_bytes),
    "deserialize_signature",
  )
  let verified = expect_frost(
    @moonfrost.prime_order_verify(
      ops,
      msg,
      sig_roundtrip,
      pub_pkg.verifying_key,
    ),
    "prime_order_verify",
  )
  if !verified {
    abort("FATAL: prime_order_verify returned false for honest signature")
  }
  let expected_len = ops.ne + ops.ns
  if sig_bytes.length() != expected_len {
    abort(
      "FATAL: unexpected signature length \{sig_bytes.length()}, expected \{expected_len}",
    )
  }
  println(
    "  [Coordinator · aggregate] 聚合完成，输出 \{sig_bytes.length()} 字节标准 Schnorr 签名:",
  )
  println("    R (\{ops.ne}B): \{hex_element(ops, sig.r)}")
  println("    z (\{ops.ns}B): \{hex_scalar(ops, sig.z)}")
  println(
    "    Signature (\{sig_bytes.length()}B): \{@crypto.bytes_to_hex(sig_bytes)}",
  )
  println(
    "  [PASS] 标准 Schnorr prime_order_verify 验签通过 (与单方签名完全不可区分)！",
  )
  (sig, sig_bytes)
}

///|
/// Simulates a Byzantine participant tampering with its Round 2 signature share,
/// verifies Coordinator's RFC 9591 §5.4 Identifiable Abort returns
/// `Err(CheaterDetected([cheater_id]))`, and optionally demonstrates Nonce reuse
/// rejection (`Err(NonceAlreadyUsed)`).
fn[S, E] run_cheater_and_defense(
  ops : @frost.SuiteOps[S, E],
  key_packages : Array[@frost.KeyPackage[S, E]],
  pub_pkg : @frost.PublicKeyPackage[E],
  signer_ids : Array[Int32],
  cheater_id : Int32,
  msg_text : String,
  seed_prefix : String,
  node_prefix : String,
  demo_nonce_reuse : Bool,
) -> Unit {
  let msg = @crypto.ascii_bytes(msg_text)
  println(
    "  Quorum   : \{format_quorum(signer_ids, node_prefix)}  |  恶意注入目标: \{node_prefix}\{cheater_id}",
  )

  let nonces_list : Array[@frost.SigningNonces[S, E]] = []
  let commitment_list : Array[@frost.CommitmentEntry[E]] = []
  for i = 0; i < signer_ids.length(); i = i + 1 {
    let id = signer_ids[i]
    let kp = key_packages[id - 1]
    let drbg = @moonfrost.drbg_from_seed(
      @crypto.ascii_bytes("\{seed_prefix}-attack-r1-node-\{id}"),
    )
    let (nonces, comms) = expect_frost(
      @moonfrost.commit(ops, kp.signing_share, drbg),
      "attack commit(\{id})",
    )
    nonces_list.push(nonces)
    commitment_list.push(@frost.CommitmentEntry::new(id, comms))
  }

  let tamper_drbg = @moonfrost.drbg_from_seed(
    @crypto.ascii_bytes("\{seed_prefix}-evil-offset"),
  )
  let evil_offset = @frost.random_nonzero_scalar(ops, tamper_drbg)
  let sig_shares : Array[@frost.SignatureShare[S]] = []
  for i = 0; i < signer_ids.length(); i = i + 1 {
    let id = signer_ids[i]
    let kp = key_packages[id - 1]
    let honest = expect_frost(
      @moonfrost.sign(ops, kp, nonces_list[i], msg, commitment_list),
      "attack sign(\{id})",
    )
    if id == cheater_id {
      let corrupted_scalar = (ops.scalar_add)(honest.share, evil_offset)
      println(
        "  [ATTACK] \{node_prefix}\{id} 在 Round 2 注入随机恶意偏移量篡改签名分片:",
      )
      println("    诚实分片 z_\{id}    : \{hex_scalar(ops, honest.share)}")
      println("    恶意偏移 delta   : \{hex_scalar(ops, evil_offset)}")
      println(
        "    篡改后分片 z'_\{id} : \{hex_scalar(ops, corrupted_scalar)}",
      )
      sig_shares.push({ identifier: id, share: corrupted_scalar, })
    } else {
      sig_shares.push(honest)
    }
  }

  println(
    "  [Coordinator · aggregate] 尝试聚合签名分片 -> 聚合验签失败 -> 触发 RFC 9591 §5.4 逐片定责:",
  )
  match @moonfrost.aggregate(ops, commitment_list, msg, pub_pkg, sig_shares) {
    Ok(_) => abort("FATAL: expected CheaterDetected but aggregate succeeded")
    Err(@frost.FrostError::CheaterDetected(cheaters)) => {
      if cheaters.length() != 1 || cheaters[0] != cheater_id {
        abort(
          "FATAL: expected CheaterDetected([\{cheater_id}]), got CheaterDetected(\{format_id_list(cheaters)})",
        )
      }
      println(
        "  [ALERT -> PASS] 精准抓出恶意节点: CheaterDetected(\{format_id_list(cheaters)}) -> 锁定作弊者 \{node_prefix}\{cheater_id}！",
      )
    }
    Err(other) =>
      abort("FATAL: expected CheaterDetected, got unexpected error: \{other}")
  }

  if demo_nonce_reuse {
    let victim_id = signer_ids[0]
    let victim_kp = key_packages[victim_id - 1]
    println("")
    println(
      "  [DEFENSE · Nonce 重用拦截] 模拟重放攻击：尝试复用 \{node_prefix}\{victim_id} 已消费的 SigningNonces (is_used=\{nonces_list[0].is_used()}):",
    )
    match
      @moonfrost.sign(ops, victim_kp, nonces_list[0], msg, commitment_list) {
      Ok(_) => abort("FATAL: expected NonceAlreadyUsed but sign succeeded")
      Err(@frost.FrostError::NonceAlreadyUsed) =>
        println(
          "  [BLOCKED -> PASS] 状态机拦截成功: Err(NonceAlreadyUsed) —— 杜绝 Schnorr Nonce 重用私钥泄露风险！",
        )
      Err(other) =>
        abort(
          "FATAL: expected NonceAlreadyUsed, got unexpected error: \{other}",
        )
    }
  }
}

///|
/// Scenario 1: 3-of-5 Decentralized Multi-Party Cold Wallet
/// Suite: FROST(ristretto255, SHA-512) · RFC 9591 §6.2
fn run_scenario_1() -> Unit {
  let ops : @frost.SuiteOps[@ristretto255.Scalar, @ristretto255.RistrettoPoint] = @moonfrost.ristretto255_sha512()
  print_section_header(
    "场景一：3-of-5 分布式多方冷钱包 (Decentralized Treasury Cold Wallet)",
    "Ciphersuite: \{@ristretto255.CONTEXT_STRING} (RFC 9591 §6.2) | Ne=\{@ristretto255.NE}B, Ns=\{@ristretto255.NS}B, Sig=\{@ristretto255.NE + @ristretto255.NS}B",
  )

  print_step_header("Step 1 · 5 节点无中心 3 轮 Pedersen DKG (t=3, n=5)")
  let (key_packages, pub_pkg) = run_pedersen_dkg(
    ops, 5, 3, "moonfrost-wallet", "Node ",
  )

  let tx_msg = "TREASURY-TX: transfer 50.00 BTC to vault-2026-gold"

  print_step_header(
    "Step 2 · 正常门限签名：法定集合 {Node 1, Node 3, Node 5} 签署金库交易",
  )
  let _ = run_honest_signing(
    ops,
    key_packages,
    pub_pkg,
    [1, 3, 5],
    tx_msg,
    "moonfrost-wallet-tx1",
    "Node ",
  )

  print_step_header(
    "Step 3 · 恶意节点攻击与精准定责 (RFC 9591 §5.4 Identifiable Abort)",
  )
  run_cheater_and_defense(
    ops,
    key_packages,
    pub_pkg,
    [1, 3, 5],
    3,
    tx_msg,
    "moonfrost-wallet-tx2",
    "Node ",
    false,
  )

  print_step_header(
    "Step 4 · 剔除作弊者 Node 3 并自愈重签：诚实集合 {Node 1, Node 2, Node 5}",
  )
  let _ = run_honest_signing(
    ops,
    key_packages,
    pub_pkg,
    [1, 2, 5],
    tx_msg,
    "moonfrost-wallet-tx3-healed",
    "Node ",
  )
}

///|
/// Scenario 2: 3-of-5 Distributed Root CA Certificate Issuance
/// Suite: FROST(P-256, SHA-256) · RFC 9591 §6.4
fn run_scenario_2() -> Unit {
  let ops : @frost.SuiteOps[@p256.Scalar, @p256.P256Point] = @moonfrost.p256_sha256()
  print_section_header(
    "场景二：3-of-5 分布式根 CA 证书签发 (Distributed HSM Root CA)",
    "Ciphersuite: \{@p256.CONTEXT_STRING} (RFC 9591 §6.4) | Ne=\{@p256.NE}B SEC1, Ns=\{@p256.NS}B, Sig=\{@p256.NE + @p256.NS}B",
  )

  print_step_header(
    "Step 1 · 5 个 HSM CA 节点无中心 3 轮 Pedersen DKG (t=3, n=5)",
  )
  let (key_packages, pub_pkg) = run_pedersen_dkg(
    ops, 5, 3, "moonfrost-root-ca", "CA-",
  )

  let cert_tbs = "X509-TBS: CN=moonfrost.dev, serial=0x2026, policy=threshold-3of5"

  print_step_header(
    "Step 2 · 正常证书签发：法定集合 {CA-1, CA-2, CA-4} 签署 X.509 TBS 载荷",
  )
  let _ = run_honest_signing(
    ops,
    key_packages,
    pub_pkg,
    [1, 2, 4],
    cert_tbs,
    "moonfrost-ca-cert1",
    "CA-",
  )

  print_step_header(
    "Step 3 · 恶意 CA-4 节点抓捕 + Nonce 重用拦截 + 自愈重签 {CA-1, CA-2, CA-3}",
  )
  run_cheater_and_defense(
    ops,
    key_packages,
    pub_pkg,
    [1, 2, 4],
    4,
    cert_tbs,
    "moonfrost-ca-cert2",
    "CA-",
    true,
  )

  println("")
  println(
    "  [HEAL · 自愈重签] 剔除恶意节点 CA-4，切换诚实法定集合 {CA-1, CA-2, CA-3} 完成根证书签发:",
  )
  let _ = run_honest_signing(
    ops,
    key_packages,
    pub_pkg,
    [1, 2, 3],
    cert_tbs,
    "moonfrost-ca-cert3-healed",
    "CA-",
  )
}

///|
/// Verifies a single IETF RFC 9591 Appendix E official test vector end-to-end.
fn[S, E] verify_rfc9591_vector(
  ops : @frost.SuiteOps[S, E],
  label : String,
  group_sk_hex : String,
  expected_pk_hex : String,
  msg_hex : String,
  coeff1_hex : String,
  p1_hiding_rand_hex : String,
  p1_binding_rand_hex : String,
  p3_hiding_rand_hex : String,
  p3_binding_rand_hex : String,
  expected_p1_share_hex : String,
  expected_p3_share_hex : String,
  expected_sig_hex : String,
) -> Unit {
  println("")
  println("  >> \{label} (\{ops.context_string})")
  let group_sk = expect_str(
    (ops.deserialize_scalar)(
      expect_str(@crypto.hex_to_bytes(group_sk_hex), "group_sk hex"),
    ),
    "deserialize group_sk",
  )
  let coeff1 = expect_str(
    (ops.deserialize_scalar)(
      expect_str(@crypto.hex_to_bytes(coeff1_hex), "coeff1 hex"),
    ),
    "deserialize coeff1",
  )
  let msg = expect_str(@crypto.hex_to_bytes(msg_hex), "msg hex")

  let (key_packages, pub_pkg, _) = expect_frost(
    @frost.trusted_dealer_keygen_with_secret(ops, group_sk, [coeff1], 3),
    "trusted_dealer_keygen_with_secret",
  )
  let pk_hex = hex_element(ops, pub_pkg.verifying_key)
  if pk_hex != expected_pk_hex {
    abort(
      "FATAL [\{label}]: group_public_key mismatch\n  got : \{pk_hex}\n  want: \{expected_pk_hex}",
    )
  }

  let kp1 = key_packages[0]
  let kp3 = key_packages[2]

  // Round 1 with RFC 9591 deterministic randomness
  let (n1, c1) = expect_frost(
    @frost.commit_with_randomness(
      ops,
      kp1.signing_share,
      expect_str(@crypto.hex_to_bytes(p1_hiding_rand_hex), "p1 hiding rand"),
      expect_str(@crypto.hex_to_bytes(p1_binding_rand_hex), "p1 binding rand"),
    ),
    "commit_with_randomness P1",
  )
  let (n3, c3) = expect_frost(
    @frost.commit_with_randomness(
      ops,
      kp3.signing_share,
      expect_str(@crypto.hex_to_bytes(p3_hiding_rand_hex), "p3 hiding rand"),
      expect_str(@crypto.hex_to_bytes(p3_binding_rand_hex), "p3 binding rand"),
    ),
    "commit_with_randomness P3",
  )
  let commitment_list : Array[@frost.CommitmentEntry[E]] = [
    @frost.CommitmentEntry::new(1, c1),
    @frost.CommitmentEntry::new(3, c3),
  ]

  // Round 2 signature shares
  let s1 = expect_frost(
    @moonfrost.sign(ops, kp1, n1, msg, commitment_list),
    "RFC sign P1",
  )
  let s3 = expect_frost(
    @moonfrost.sign(ops, kp3, n3, msg, commitment_list),
    "RFC sign P3",
  )
  let p1_share_hex = hex_scalar(ops, s1.share)
  let p3_share_hex = hex_scalar(ops, s3.share)
  if p1_share_hex != expected_p1_share_hex {
    abort(
      "FATAL [\{label}]: P1 sig_share mismatch\n  got : \{p1_share_hex}\n  want: \{expected_p1_share_hex}",
    )
  }
  if p3_share_hex != expected_p3_share_hex {
    abort(
      "FATAL [\{label}]: P3 sig_share mismatch\n  got : \{p3_share_hex}\n  want: \{expected_p3_share_hex}",
    )
  }

  // Coordinator aggregate + serialize + verify
  let sig = expect_frost(
    @moonfrost.aggregate(ops, commitment_list, msg, pub_pkg, [s1, s3]),
    "RFC aggregate",
  )
  let sig_bytes = expect_frost(
    @moonfrost.serialize_signature(ops, sig),
    "RFC serialize_signature",
  )
  let expected_sig_bytes = expect_str(
    @crypto.hex_to_bytes(expected_sig_hex),
    "expected sig hex",
  )
  let sig_hex = @crypto.bytes_to_hex(sig_bytes)
  let verified = expect_frost(
    @moonfrost.prime_order_verify(ops, msg, sig, pub_pkg.verifying_key),
    "RFC prime_order_verify",
  )
  if !verified ||
    !@crypto.ct_eq_bytes(sig_bytes, expected_sig_bytes) ||
    sig_hex != expected_sig_hex {
    abort(
      "FATAL [\{label}]: RFC 9591 signature mismatch\n  got : \{sig_hex}\n  want: \{expected_sig_hex}",
    )
  }
  let sig_len = sig_bytes.length()
  println("     Group PK   : \{pk_hex}")
  println("     P1 Share   : \{p1_share_hex}  [OK]")
  println("     P3 Share   : \{p3_share_hex}  [OK]")
  println("     Computed   : \{sig_hex}")
  println("     RFC 9591   : \{expected_sig_hex}")
  println(
    "     [PASS] \{sig_len}/\{sig_len} bytes exact match & prime_order_verify == true",
  )
}

///|
/// Scenario 3: Live Verification of IETF RFC 9591 Appendix E.3 & E.4 Test Vectors
fn run_scenario_3() -> Unit {
  print_section_header(
    "场景三：IETF RFC 9591 Appendix E.3 & E.4 官方向量现场核验", "Deterministic 2-of-3 Signing (Participants {1, 3}, Message = 0x74657374 \"test\")",
  )

  verify_rfc9591_vector(
    @moonfrost.ristretto255_sha512(),
    "RFC 9591 Appendix E.3 · FROST(ristretto255, SHA-512)",
    "1b25a55e463cfd15cf14a5d3acc3d15053f08da49c8afcf3ab265f2ebc4f970b",
    "e2a62f39eede11269e3bd5a7d97554f5ca384f9f6d3dd9c3c0d05083c7254f57",
    "74657374",
    "410f8b744b19325891d73736923525a4f596c805d060dfb9c98009d34e3fec02",
    "f595a133b4d95c6e1f79887220c8b275ce6277e7f68a6640e1e7140f9be2fb5c",
    "34dd1001360e3513cb37bebfabe7be4a32c5bb91ba19fbd4360d039111f0fbdc",
    "daa0cf42a32617786d390e0c7edfbf2efbd428037069357b5173ae61d6dd5d5e",
    "b4387e72b2e4108ce4168931cc2c7fcce5f345a5297368952c18b5fc8473f050",
    "9285f875923ce7e0c491a592e9ea1865ec1b823ead4854b48c8a46287749ee09",
    "7cb211fe0e3d59d25db6e36b3fb32344794139602a7b24f1ae0dc4e26ad7b908",
    "fc45655fbc66bbffad654ea4ce5fdae253a49a64ace25d9adb62010dd9fb25552164141787162e5b4cab915b4aa45d94655dbb9ed7c378a53b980a0be220a802",
  )

  verify_rfc9591_vector(
    @moonfrost.p256_sha256(),
    "RFC 9591 Appendix E.4 · FROST(P-256, SHA-256)",
    "8ba9bba2e0fd8c4767154d35a0b7562244a4aaf6f36c8fb8735fa48b301bd8de",
    "023a309ad94e9fe8a7ba45dfc58f38bf091959d3c99cfbd02b4dc00585ec45ab70",
    "74657374",
    "80f25e6c0709353e46bfbe882a11bdbb1f8097e46340eb8673b7e14556e6c3a4",
    "ec4c891c85fee802a9d757a67d1252e7f4e5efb8a538991ac18fbd0e06fb6fd3",
    "9334e29d09061223f69a09421715a347e4e6deba77444c8f42b0c833f80f4ef9",
    "c0451c5a0a5480d6c1f860e5db7d655233dca2669fd90ff048454b8ce983367b",
    "2ba5f7793ae700e40e78937a82f407dd35e847e33d1e607b5c7eb6ed2a8ed799",
    "400308eaed7a2ddee02a265abe6a1cfe04d946ee8720768899619cfabe7a3aeb",
    "561da3c179edbb0502d941bb3e3ace3c37d122aaa46fb54499f15f3a3331de44",
    "026d8d434874f87bdb7bc0dfd239b2c00639044f9dcb195e9a04426f70bfa4b70d9620acac6767e8e3e3036815fca4eb3a3caa69992b902bcd3352fc34f1ac192f",
  )
}

///|
fn main {
  println(
    "##############################################################################",
  )
  println(
    "#  MoonFROST · Pure MoonBit Zero-FFI RFC 9591 FROST Threshold Signature CLI  #",
  )
  println(
    "#  Pedersen DKG · 2-Round Signing · Identifiable Abort · Nonce-Reuse Guard   #",
  )
  println(
    "##############################################################################",
  )

  run_scenario_1()
  run_scenario_2()
  run_scenario_3()

  println("")
  println(
    "==============================================================================",
  )
  println(
    "  ALL SCENARIOS PASSED · MoonFROST End-to-End Verification Complete!",
  )
  println(
    "    [OK] 场景一: Ristretto255 3-of-5 分布式冷钱包 DKG + 签名 + 抓捕 Node 3 + 自愈",
  )
  println(
    "    [OK] 场景二: P-256 3-of-5 分布式根 CA DKG + 签名 + 抓捕 CA-4 + Nonce 防重用 + 自愈",
  )
  println(
    "    [OK] 场景三: IETF RFC 9591 Appendix E.3 (64B) & E.4 (65B) 官方向量 100% 精确匹配",
  )
  println(
    "==============================================================================",
  )
}
