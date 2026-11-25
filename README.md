# MoonFROST (`CoolrfulDARkness/moonfrost`)

> **纯 MoonBit、零 FFI、恒定时间防侧信道的 IETF RFC 9591 FROST 两轮门限 Schnorr 签名协议栈**  
> 同时完整支持 `FROST(ristretto255, SHA-512)` (§6.2) 与 `FROST(P-256, SHA-256)` (§6.4)，内置无中心 3 轮 **Pedersen DKG**、**Feldman VSS** 与 RFC 9591 §5.4 **精准作弊者定责（Identifiable Abort）**，覆盖 `wasm` / `js` / `native` 三端零警告运行。

---

## 核心亮点

- **100% 纯 MoonBit · 零外部依赖 · 零 `extern` FFI**：从 SHA-256/SHA-512、RFC 9380 `expand_message_xmd`、ChaCha20 DRBG 到 Ristretto255 / P-256 素域与椭圆曲线群算术全部原生编写，CI 内置零 `extern` 静态门禁强制校验。
- **恒定时间防侧信道密码学基座**：
  - **Ristretto255 (RFC 9496)**：`5 × 51-bit` $\mathbb{F}_{2^{255}-19}$ 域算术、Ed25519 扩展坐标完备群律、完整规范编解码与 Elligator2 映射，彻底消除 8 阶辅因子攻击面。
  - **NIST P-256 (SEC 1)**：`4 × 64-bit` Montgomery 域与标量算术、Renes-Costello-Batina (2015) $a=-3$ 完备射影加法/倍点公式、33 字节严格 SEC 1 压缩编解码。
  - **双套件统一防护**：4-bit 固定窗口 + 16 项全表恒定时间扫描（零 secret 分支、零 secret 查表索引）、费马小定理恒定时间求逆、防死存储消除内存清零。
- **`SuiteOps[S, E]` 泛型零重复引擎**：全部 FROST 协议状态机、多项式插值、Feldman VSS、Pedersen DKG 与签名聚合仅实现一份泛型代码，双套件 100% 同构、零代码重复。
- **纵深协议安全机制**：
  - **无中心 3 轮 Pedersen DKG**：内置域分离 `H_dkg` Schnorr 知识证明（防御 Rogue-Key 攻击）与 Feldman VSS 分片验证（双阶段精准定责）。
  - **RFC 9591 §5.4 Identifiable Abort**：聚合验签失败自动触发逐片追责，精准返回全部作弊节点 ID `FrostError::CheaterDetected(cheaters)`。
  - **One-Time Nonce 强制守卫**：`SigningNonces` 全字段私有，调用 `sign` 时立即消费并覆写为 `scalar_zero()`，任何二次复用确定性拦截为 `FrostError::NonceAlreadyUsed`。
- **100% RFC 9591 Appendix E 逐字节吻合**：完整通过 IETF RFC 9591 Appendix E.3 (`FROST(ristretto255, SHA-512)`) 与 Appendix E.4 (`FROST(P-256, SHA-256)`) 全部中间值与最终聚合签名（64B / 65B）逐字节断言。
- **三端零警告原生运行**：`wasm`、`js`、`native` 三端统一通过 `moon check -d`、`moon test -d` 与 `moon run cmd/main` 冒烟验证。

---

## 快速上手

确保已安装 MoonBit 工具链（`moon version`），在项目根目录执行：

```bash
# 1. 运行三端零警告完整测试套件
moon test --target wasm -d
moon test --target js -d
moon test --target native -d

# 2. 一键运行演示 CLI（3-of-5 分布式钱包 + 3-of-5 根 CA + 抓出恶意节点 + RFC 9591 E.3/E.4 现场核验）
moon run cmd/main --target wasm
moon run cmd/main --target js
moon run cmd/main --target native

# 3. 运行三端 Release 性能基准
moon bench --target wasm --release
moon bench --target js --release
moon bench --target native --release
```

---

## 代码示例：3-of-5 无中心 Pedersen DKG + 两轮门限签名 + 作弊者定责

以下示例严格对应顶层门面 [`moonfrost.mbt`](moonfrost.mbt) 的真实公开 API（将 `ristretto255_sha512()` 替换为 `p256_sha256()` 即可无缝切换至 NIST P-256 套件）：

```moonbit nocheck
///|
fn demo_3of5_dkg_and_cheater_detection() -> Unit {
  let ops = @moonfrost.ristretto255_sha512()
  let drbg = @moonfrost.drbg_from_seed(b"moonfrost-3of5-demo-seed")
  let max_signers = 5
  let min_signers = 3

  // 1) 无中心 3 轮 Pedersen DKG（零可信第三方）
  let r1_secrets = []
  let r1_packages = []
  for id = 1; id <= max_signers; id = id + 1 {
    let (sec, pkg) = @moonfrost.dkg_part1(
      ops, id, max_signers, min_signers, drbg,
    ).unwrap()
    r1_secrets.push(sec)
    r1_packages.push(pkg)
  }

  let r2_secrets = []
  let all_r2_packages = []
  for i = 0; i < max_signers; i = i + 1 {
    let (sec2, pkgs2) = @moonfrost.dkg_part2(ops, r1_secrets[i], r1_packages).unwrap()
    r2_secrets.push(sec2)
    for j = 0; j < pkgs2.length(); j = j + 1 {
      all_r2_packages.push(pkgs2[j])
    }
  }

  let key_packages = []
  let mut group_pub_opt : @moonfrost.PublicKeyPackage[_]? = None
  for i = 0; i < max_signers; i = i + 1 {
    let my_id = i + 1
    let my_r2 = []
    for j = 0; j < all_r2_packages.length(); j = j + 1 {
      if all_r2_packages[j].receiver == my_id {
        my_r2.push(all_r2_packages[j])
      }
    }
    let (kp, pub_pkg) = @moonfrost.dkg_part3(
      ops,
      r2_secrets[i],
      r1_packages,
      my_r2,
    ).unwrap()
    key_packages.push(kp)
    group_pub_opt = Some(pub_pkg)
  }
  let pub_pkg = group_pub_opt.unwrap()

  // 2) RFC 9591 两轮门限签名：由子集 {Node 1, Node 3, Node 5} 签名
  let msg = b"TREASURY-TX: transfer 50.00 BTC to vault-2026"
  let (n1, c1) = @moonfrost.commit(ops, key_packages[0].signing_share, drbg).unwrap()
  let (n3, c3) = @moonfrost.commit(ops, key_packages[2].signing_share, drbg).unwrap()
  let (n5, c5) = @moonfrost.commit(ops, key_packages[4].signing_share, drbg).unwrap()

  // 严格按参与者 ID 升序构造承诺列表
  let commitment_list : Array[@moonfrost.CommitmentEntry[_]] = [
    @moonfrost.CommitmentEntry::new(1, c1),
    @moonfrost.CommitmentEntry::new(3, c3),
    @moonfrost.CommitmentEntry::new(5, c5),
  ]

  // sign() 自动消费并清零 SigningNonces；重复调用将返回 Err(NonceAlreadyUsed)
  let s1 = @moonfrost.sign(ops, key_packages[0], n1, msg, commitment_list).unwrap()
  let s3 = @moonfrost.sign(ops, key_packages[2], n3, msg, commitment_list).unwrap()
  let s5 = @moonfrost.sign(ops, key_packages[4], n5, msg, commitment_list).unwrap()

  // Coordinator 聚合 + 标准单方 Schnorr 验签
  let sig = @moonfrost.aggregate(ops, commitment_list, msg, pub_pkg, [
    s1, s3, s5,
  ]).unwrap()
  let sig_bytes = @moonfrost.serialize_signature(ops, sig).unwrap()
  let decoded = @moonfrost.deserialize_signature(ops, sig_bytes).unwrap()
  let ok = @moonfrost.prime_order_verify(
    ops,
    msg,
    decoded,
    pub_pkg.verifying_key,
  ).unwrap()
  println("Threshold signature valid: \{ok} (\{sig_bytes.length()} bytes)")

  // 3) RFC 9591 §5.4 Identifiable Abort：模拟 Node 3 注入恶意分片并精准抓捕
  let bad_s3 : @moonfrost.SignatureShare[_] = {
    identifier: 3,
    share: (ops.scalar_add)(s3.share, (ops.scalar_one)()),
  }
  match
    @moonfrost.aggregate(ops, commitment_list, msg, pub_pkg, [s1, bad_s3, s5]) {
    Err(@moonfrost.FrostError::CheaterDetected(ids)) =>
      println("Caught malicious signer(s): \{ids}") // 输出: [3]
    _ => ()
  }
}
```

---

## 性能基准与三端验证

实测环境：`moon 0.1.20261119` / `moonc v0.10.22+124d61d05`（Windows x86_64），全仓库 **58 / 58 测试**（含 RFC 9591 Appendix E.3/E.4 全量向量 + **26 项安全对抗测试**）在 `wasm` / `js` / `native` 三端 `-d` 零警告通过，零 `extern` FFI。

三端 `--release` `moon bench` 实测数据（`10 / 10 passed`）：

| 基准项 | `wasm` (`--release`) | `native` (`--release`, tcc) | `js` (`--release`, Node v22) |
| :--- | ---: | ---: | ---: |
| `Ristretto255` 3-of-5 Pedersen DKG（5 节点全 3 轮） | `995.24 ms ± 6.99 ms` | `1.34 s ± 15.95 ms` | `3.32 s ± 41.93 ms` |
| `Ristretto255` Round 1 `commit` | `9.72 ms ± 125.13 µs` | `12.91 ms ± 108.17 µs` | `32.46 ms ± 639.00 µs` |
| `Ristretto255` Round 2 `sign`（含 fresh commit） | `29.59 ms ± 325.54 µs` | `40.52 ms ± 339.11 µs` | `100.29 ms ± 1.47 ms` |
| `Ristretto255` 3-of-5 `aggregate` + 验签 | `28.39 ms ± 257.98 µs` | `38.87 ms ± 459.97 µs` | `97.96 ms ± 1.96 ms` |
| `Ristretto255` 标准 Schnorr `verify` | `10.63 ms ± 67.67 µs` | `14.36 ms ± 97.77 µs` | `35.90 ms ± 700.47 µs` |
| `NIST P-256` 3-of-5 Pedersen DKG（5 节点全 3 轮） | `2.25 s ± 37.70 ms` | `3.43 s ± 23.31 ms` | `5.53 s ± 44.29 ms` |
| `NIST P-256` Round 1 `commit` | `22.74 ms ± 283.67 µs` | `33.46 ms ± 269.02 µs` | `73.37 ms ± 921.77 µs` |
| `NIST P-256` Round 2 `sign`（含 fresh commit） | `59.78 ms ± 666.75 µs` | `95.80 ms ± 1.22 ms` | `218.88 ms ± 5.82 ms` |
| `NIST P-256` 3-of-5 `aggregate` + 验签 | `59.28 ms ± 670.03 µs` | `93.12 ms ± 1.25 ms` | `207.39 ms ± 2.93 ms` |
| `NIST P-256` 标准 Schnorr `verify` | `23.98 ms ± 176.39 µs` | `38.92 ms ± 688.16 µs` | `77.44 ms ± 773.76 µs` |

---

## 架构与文档导航

| 文档 / 配置 | 内容说明 |
| :--- | :--- |
| [架构设计文档 (`docs/ARCHITECTURE.md`)](docs/ARCHITECTURE.md) | 分层架构图、Ristretto255/P-256 数学与恒定时间工程、`SuiteOps[S, E]` 泛型引擎、2-Round 签名与 3-Round Pedersen DKG 时序图、全模块目录与公开 API 索引 |
| [安全验证与合规报告 (`docs/SECURITY_VERIFICATION.md`)](docs/SECURITY_VERIFICATION.md) | 威胁模型、EUF-CMA 安全目标、恒定时间审计清单、Nonce 清零防重用机制、RFC 9591 / RFC 9496 / RFC 9380 逐条合规矩阵与实测结果 |
| [CI 工作流 (`.github/workflows/ci.yml`)](.github/workflows/ci.yml) | `moon fmt --check`、零 `extern` FFI 静态门禁、README 同步检查、`wasm`/`js`/`native` 三端 `-d` 零警告测试、CLI 冒烟与基准验证 |
| [顶层门面源码 (`moonfrost.mbt`)](moonfrost.mbt) | 统一对外导出 API 与类型别名 |

---

## 许可证

本项目基于 [Apache License 2.0](LICENSE) 开源许可发布。
