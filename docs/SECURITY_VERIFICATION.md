# MoonFROST 安全模型、RFC 合规矩阵与验证报告

本文档系统阐述 `CoolrfulDARkness/moonfrost` 的密码学安全模型、恒定时间与内存安全审计清单、Nonce 一次性消费与清零机制、IETF RFC 9591 / RFC 9496 / RFC 9380 逐条合规矩阵，以及测试向量与安全对抗验证覆盖范围。

---

## 1. 威胁模型与安全目标

### 1.1 敌手能力假设

MoonFROST 面向强敌手环境设计，覆盖以下威胁：

1. **门限腐化敌手（$t-1$ Compromise）**：敌手可控制最多 `min_signers - 1` 个签名节点并窃取其完整内部密钥材料 `KeyPackage`，同时完全控制网络协调者（Coordinator），任意延迟、重排、篡改或中止网络消息。
2. **并发签名会话敌手（ROS / Wagner Generalized Birthday Attack）**：敌手可并发发起多个签名会话，试图线性组合不同会话的承诺以伪造未授权消息的签名。
3. **恶意密钥生成敌手（Rogue-Key Attack in DKG）**：在无中心 DKG 阶段，恶意节点可延迟提交自己的公钥承诺，试图通过抵消诚实节点公钥来控制最终群公钥，或在 Round 2 向诚实节点投递错误秘密分片实施拒绝服务（DoS）。
4. **恶意签名分片与重放敌手**：恶意参与者可在 Round 2 提交伪造签名分片破坏聚合，或恶意协调者试图诱导诚实节点复用同一份 Round 1 Nonce 对两条不同消息签名（从而通过两个线性方程直接解出私钥分片 $sk_i$）。
5. **非规范输入与畸形编码敌手**：攻击者向解析层注入非规范标量（$\ge \ell$ 或 $\ge n$）、非曲线点、单位元编码、未压缩点前缀、截断或超长签名，试图触发签名延展性（Malleability）、小子群泄漏或运行时崩溃。
6. **时序与缓存侧信道敌手**：攻击者通过精确测量签名者执行耗时或观察缓存访问模式，试图恢复长期私钥分片 $sk_i$ 或一次性 Nonce $(d_i, e_i)$。

### 1.2 核心安全属性

- **存在性不可伪造性（EUF-CMA）**：遵循 Komlo-Goldberg (SAC 2020) 与 Bellare-Crites-Komlo-Malluhi-Tessaro-Zhu (CRYPTO 2022) 对 FROST 的安全性证明，在离散对数困难假设与随机预言机模型下，即使并发开启多会话，任意控制少于 $t$ 个节点的 PPT 敌手也无法伪造合法的群 Schnorr 签名。
- **签名不可区分性（Output Indistinguishability）**：输出的 $(R, z)$ 严格符合 RFC 9591 Appendix A/B 标准素数阶 Schnorr 签名格式，验证方使用标准单方 `prime_order_verify` 即可验签，无法从签名本身区分门限规模 $(t, n)$ 或参与签名的具体子集。
- **可识别中止（Identifiable Abort, RFC 9591 §5.4）**：当聚合验签失败时，Coordinator 通过公开的 `PublicKeyPackage` 逐片验证所有参与者的签名分片，100% 精准归因全部作弊者 ID（`FrostError::CheaterDetected(Array[Int])`），支持上层自动剔除恶意节点并自愈重签。
- **零 FFI 内存安全边界**：全项目由纯 MoonBit 编写并通过 CI 静态门禁强制校验零 `extern` 声明，在 Wasm、JS、Native 三端均享受强类型与数组越界保护。

---

## 2. 恒定时间与内存安全审计清单

| 模块 / 文件 | 涉及秘密数据 | 恒定时间实现机制 | 审计要点与状态 |
| :--- | :--- | :--- | :--- |
| `crypto/ct.mbt` | 字节数组、标量掩码 | 纯位运算 `ct_mask_from_bit`, `ct_is_zero_u64`, `ct_eq_u64`, `ct_select_*`, `ct_eq_bytes`；`zeroize_bytes`/`zeroize_u64` 经全局 `zeroize_sink` 防死存储消除 | 无分支掩码、全长字节扫描 |
| `ristretto255/field.mbt` | 域元素、坐标投影 | `5×51-bit` 无分支加减乘（`4p` 偏置 + 宽乘）、`Fe::ct_select`、`Fe::ct_eq`、`sqrt_ratio_m1` 固定指数幂 | 无 secret 分支，费马幂指公开常量 |
| `ristretto255/point.mbt` | $sk_i, d_i, e_i$ 标量乘 | Hisil 2008 完备点加与倍点；4-bit 固定窗口 + 16 项全表 CT 扫描 `ct_lookup_point` | 全部 64 nibble 固定扫描 0..15，零 secret 查表索引 |
| `ristretto255/ristretto.mbt` | 群元素编码/比较 | `encode` 使用 `Fe::ct_select` 与 `ct_abs`；`ct_eq` 双陪集恒定时间判定；`EdwardsPoint` 私有封装 | 无辅因子暴露，非单位元校验完备 |
| `ristretto255/scalar.mbt` | $sk_i, d_i, e_i, z_i$ | 4×64-bit 无分支 `sub_borrow_u64` 与 Montgomery 乘；费马小定理 $s^{\ell-2} \bmod \ell$ 固定 253 位扫描求逆 | 零 EGCD 分支，严格规范解码（`< l`） |
| `p256/field.mbt` | 域元素、坐标投影 | `4×64-bit` Montgomery 域无分支 `adc`/`sbb`/`mul64`、`FieldElement::ct_select`、费马求逆 $a^{p-2} \bmod p$ | 无 secret 分支 |
| `p256/point.mbt` | $sk_i, d_i, e_i$ 标量乘 | Renes-Costello-Batina 2015 $a=-3$ 完备加法 (Alg. 4) 与倍点 (Alg. 6)；4-bit 固定窗口 + 16 项全表 CT 扫描 `ct_table_lookup` | 零点加例外分支，零 secret 查表索引 |
| `p256/scalar.mbt` | $sk_i, d_i, e_i, z_i$ | `4×64-bit` Montgomery 标量算术；费马小定理 $s^{n-2} \bmod n$ 固定 256 位扫描求逆；48B Horner 归约 | 零 EGCD 分支，严格规范解码（`< n`） |
| `frost/nonce.mbt` | Round 1 签名 Nonce | `SigningNonces` 全字段 `priv`；`consume()` 强制覆写 `scalar_zero()` 并置位 `used = true` | 严禁二次签名复用，Hedged Nonce 纵深防御 |

> **客观安全边界说明（Managed Runtime Transparency）**：
> 1. MoonBit 编译至 Wasm / JS / Native 托管运行时环境，语言层无法直接控制底层 CPU 寄存器分配或垃圾回收器的副本回收时机。因此，MoonFROST 在协议层通过显式覆写结构体字段为 `scalar_zero()`、在 `crypto/ct.mbt` 通过 `zeroize_sink` 防止编译器死存储消除，最大限度缩短敏感内存存活窗口。
> 2. `crypto/drbg.mbt` 提供确定性 ChaCha20/SHA-256 DRBG，便于 RFC 向量复现与跨端一致演示；**生产环境部署时，调用方必须使用操作系统 CSPRNG（如 `/dev/urandom`、`getrandom`、`BCryptGenRandom` 或 Web Crypto `crypto.getRandomValues`）提供至少 256-bit 真随机种子并在会话间定期 `reseed`**。

---

## 3. Nonce 一次性消费与清零机制（防私钥提取）

在 Schnorr 与 FROST 门限签名中，**同一份签名 Nonce 若被用于两条不同消息（或不同绑定因子上下文），敌手可直接通过两个签名分片的差值代数求解出签名者的长期私钥分片 $sk_i$**。MoonFROST 在 `frost/nonce.mbt` 与 `frost/signing.mbt` 中构建了四重防线：

1. **Hedged Nonce 生成（RFC 9591 §4.1）**：
   - `commit` 每次采样两份独立 32 字节随机数，通过 `H3(random_bytes || SerializeScalar(secret_share))` 派生 `hiding_nonce` 与 `binding_nonce`，并拒绝零标量（防止单位元承诺）。
2. **类型封装隔离（Zero Secret Leakage）**：
   - `SigningNonces[S, E]` 的 `hiding`、`binding`、`commitments`、`used` 四个字段全部声明为 `priv`，外部代码仅能读取公开的 `commitments()` 与状态 `is_used()`，无法拷贝或导出私密标量。
3. **签名者侧承诺一致性校验（RFC 9591 §5.2）**：
   - `sign()` 在消费 Nonce 之前，严格校验 `commitment_list` 非空且达到 `min_signers`、严格升序、无重复 ID、无单位元，且**必须精确包含本节点自身与 `nonces.commitments()` 完全匹配的 `(D_i, E_i)`**；若协调者试图偷换承诺，立即返回 `Err(FrostError::CommitmentMismatch(id))`。
4. **原子消费与立即清零**：
   - 在计算 $z_i$ 前，`sign()` 调用包内私有方法 `nonces.consume(ops)`：若 `used == true` 立即返回 `Err(FrostError::NonceAlreadyUsed)`；否则取出 `(h, b)` 后立刻将 `self.hiding` 与 `self.binding` 覆写为 `(ops.scalar_zero)()` 并将 `self.used` 置为 `true`。任何后续重用尝试均被确定性拦截。

---

## 4. IETF RFC 规范逐条合规矩阵

### 4.1 IETF RFC 9591 (FROST) 合规对照表

| RFC 9591 章节 | 规范要求 | MoonFROST 实现位置与细节 | 合规状态 |
| :--- | :--- | :--- | :--- |
| §3 Prime-Order Group | 素数阶群抽象、`SerializeElement` / `DeserializeElement` 拒绝单位元、`SerializeScalar` / `DeserializeScalar` 规范性 | `frost/suite_ops.mbt`, `ristretto255/`, `p256/` | 完全合规 |
| §4.1 Nonce Generation | `nonce_generate(secret)`: `H3(random_bytes[32] \|\| SerializeScalar(secret))` | `frost/nonce.mbt`: `nonce_generate`, `nonce_generate_with_randomness` | 完全合规 |
| §4.2 Polynomials & Lagrange | `derive_interpolating_value(L, x_i)` 校验 ID 合法且无重复 | `frost/poly.mbt`: `derive_interpolating_value` | 完全合规 |
| §4.3 Commitment List | 严格按参与者 ID 升序校验并规范拼接 `Ser(i) \|\| Ser(D_i) \|\| Ser(E_i)` | `frost/signing.mbt`: `validate_commitment_list`, `encode_group_commitment_list` | 完全合规 |
| §4.4 Binding Factors | `rho_i = H1(Ser(PK) \|\| H4(msg) \|\| H5(encoded_comm) \|\| Ser(i))` | `frost/signing.mbt`: `compute_binding_factor_inputs`, `compute_binding_factors` | 完全合规 |
| §4.5 Group Commitment | $R = \sum (D_i + \rho_i \cdot E_i)$，拒绝结果为单位元 | `frost/signing.mbt`: `compute_group_commitment` | 完全合规 |
| §4.6 Challenge | $c = H_2(\text{Ser}(R) \parallel \text{Ser}(PK) \parallel \text{msg})$ | `frost/signing.mbt`: `compute_challenge` | 完全合规 |
| §5.1 Round 1 Commit | 生成双 Nonce 及双承诺，私密保存 Nonce 并确保一次性使用 | `frost/nonce.mbt`: `commit`, `commit_with_randomness`, `SigningNonces` | 完全合规 |
| §5.2 Round 2 Sign | 校验列表升序/阈值/自身承诺，消费清零 Nonce，计算 $z_i = d_i + e_i \rho_i + \lambda_i s_i c$ | `frost/signing.mbt`: `sign` | 完全合规 |
| §5.3 Aggregate & Verify | 聚合 $z = \sum z_i$ 并执行群公钥验签；提供单分片验证 `verify_signature_share` | `frost/signing.mbt`: `aggregate`, `verify_signature_share` | 完全合规 |
| §5.4 Identifiable Abort | 聚合失败时逐片验证并识别全部作弊者 ID | `frost/signing.mbt`: `aggregate` 自动返回 `Err(FrostError::CheaterDetected(sorted_ids))` | 完全合规 |
| §6.2 FROST(ristretto255, SHA-512) | Context `"FROST-RISTRETTO255-SHA512-v1"`, `Ne=32, Ns=32`, SHA-512 + 64B 宽归约 | `ristretto255/suite.mbt`, `frost/suites.mbt` | 完全合规 |
| §6.4 FROST(P-256, SHA-256) | Context `"FROST-P256-SHA256-v1"`, `Ne=33, Ns=32`, XMD-SHA256 `L=48` + SEC1 压缩点 | `p256/suite.mbt`, `frost/suites.mbt` | 完全合规 |
| §7 Security Considerations | Nonce 防重用清零、恒定时间群/域运算、严格规范解析、输入边界校验 | 全栈贯彻（详见第 2、3 节） | 完全合规 |
| Appendix A | 规范签名序列化/反序列化 `R[Ne] \|\| z[Ns]`，严格校验长度、非单位元 `R` 与规范 `z` | `frost/signing.mbt`: `serialize_signature`, `deserialize_signature` | 完全合规 |
| Appendix B | 单方素数阶 Schnorr 签名与验签 `prime_order_sign` / `prime_order_verify` | `frost/signing.mbt` | 完全合规 |
| Appendix C | Trusted Dealer Shamir 分片与 Feldman VSS (`vss_commit`, `vss_verify`, `derive_group_info`) | `frost/vss.mbt`, `frost/poly.mbt` | 完全合规 |
| Appendix D | 均匀随机标量生成（D.2 宽归约主路径 + D.1 拒绝采样回退） | `frost/suites.mbt`: `random_scalar`, `random_nonzero_scalar` | 完全合规 |
| Appendix E.3 & E.4 | 官方 2-of-3 全链路中间值与最终聚合签名逐字节校验 | `frost/frost_test.mbt`, `tests/rfc9591_vectors_test.mbt`, `cmd/main/main.mbt` | 完全合规 |

### 4.2 关联 RFC 与扩展协议合规对照表

| 标准 / 协议 | 覆盖条款与功能 | 实现位置 |
| :--- | :--- | :--- |
| **IETF RFC 9496** (Ristretto255) | §4.3.1 Decode、§4.3.2 Encode、§4.3.3 Equals、§4.3.4 Elligator2 `from_uniform_bytes`、§4.4 64B 标量宽归约、§6 封装 | `ristretto255/` |
| **IETF RFC 9380** (Hash to Curve) | §5.3.1 `expand_message_xmd` (SHA-256, `b_in_bytes=32, s_in_bytes=64`, DST 长度与 `ell` 边界检查) | `crypto/xmd.mbt` |
| **FIPS 180-4** (SHS) | 流式与一次性 SHA-256、SHA-512 | `crypto/sha256.mbt`, `crypto/sha512.mbt` |
| **RFC 8439** (ChaCha20) | 确定性 ChaCha20/SHA-256 DRBG (`from_seed`, `next_bytes`, `reseed`) | `crypto/drbg.mbt` |
| **Komlo-Goldberg FROST Fig. 1** | 无中心 3 轮 Pedersen DKG + 域分离 `H_dkg` Schnorr PoK + Round 1/2 双阶段作弊者定责 | `frost/dkg.mbt` |

---

## 5. 测试向量、安全对抗与三端验证结果

### 5.1 标准向量与对抗验证覆盖矩阵

MoonFROST 在单元测试与独立验证包 `tests/` 中建立了多层次验证体系：

1. **底层密码学标准向量**：
   - FIPS 180-4 SHA-256 / SHA-512 官方向量（空输入、`"abc"`、多块消息）
   - RFC 9380 `expand_message_xmd(SHA-256)` 官方向量及边界拒绝测试
   - RFC 9496 Ristretto255 编解码、非法编码拒绝、陪集等价与 Elligator2 官方向量
   - NIST P-256 域/标量/SEC 1 压缩编解码、曲线点群律边界（$\mathcal{O}+P$, $P+P$, $P+(-P)$）与非法点拒绝
2. **RFC 9591 Appendix E.3 & E.4 全链路逐字节核验**：
   - 覆盖 `FROST(ristretto255, SHA-512)` 与 `FROST(P-256, SHA-256)` 全部中间产物：`group_public_key`、各参与方 `signing_share`（含 VSS 校验）、`hiding_nonce` / `binding_nonce`、`hiding_nonce_commitment` / `binding_nonce_commitment`、`binding_factor_input`、`binding_factor`、`sig_share`、`verify_signature_share == true`、最终 64B/65B 规范聚合签名 `sig` 与标准 `prime_order_verify == true`。
3. **安全对抗与边界攻击验证**：
   - **Nonce 一次性防重用**：二次调用 `sign` 必返回 `Err(FrostError::NonceAlreadyUsed)` 且 `is_used() == true`。
   - **承诺列表篡改与恶意协调者**：未排序列表（`UnsortedCommitments`）、重复 ID（`DuplicateParticipant`）、零/负/越界 ID（`InvalidParticipantId`）、人数不足阈值（`InsufficientParticipants`）、单位元承诺（`IdentityElement`）、偷换签名者自身承诺（`CommitmentMismatch`）。
   - **Identifiable Abort (§5.4)**：单作弊者、多作弊者同时投毒、错误消息/错误公钥聚合，均精准定位全部作弊者 ID。
   - **Pedersen DKG 对抗**：Round 1 伪造 Schnorr PoK 或单位元 `pok_r`（`InvalidDkgProof`）、Round 2 单/多发送者投递错误分片（`CheaterDetected`）、重复或越界包拒绝、任意 $t$ 节点子集门限签名一致性验证。
   - **规范编码与延展性防御**：非规范标量（`>= l` / `>= n`）、非法前缀或非曲线点、签名截断/加长（`InvalidSignatureLength`）、单位元 $R$ 签名（`IdentityElement`）、跨消息/跨公钥验签拒绝。

### 5.2 三端全量测试汇总

实测环境：`moon 0.1.20261119` / `moonc v0.10.22+124d61d05`（Windows x86_64，零 `extern` FFI 静态门禁通过）。

| 验证维度 | `wasm` (`-d`) | `js` (`-d`) | `native` (`-d`) | 说明 |
| :--- | :---: | :---: | :---: | :--- |
| `moon check --no-mbti -d` | **0 warnings** | **0 warnings** | **0 warnings** | 全仓库 7 个包严格零警告 |
| `moon test -d` | **58 / 58 PASS** | **58 / 58 PASS** | **58 / 58 PASS** | 含 `crypto`(7) + `ristretto255`(9) + `p256`(6) + `frost`(7) + 根门面(1) + `tests`(28) |
| RFC 9591 Appendix E.3 & E.4 | **100% 字节吻合** | **100% 字节吻合** | **100% 字节吻合** | 双套件 Round 1 / Round 2 / 最终 64B & 65B 签名逐字节匹配 |
| 安全对抗测试 (`tests/security_adversarial_test.mbt`) | **26 / 26 PASS** | **26 / 26 PASS** | **26 / 26 PASS** | 覆盖作弊定责、Nonce 重用、非规范编码、DKG 投毒与重放攻击 |
| `moon run cmd/main` 冒烟 | **PASS (exit 0)** | **PASS (exit 0)** | **PASS (exit 0)** | 3-of-5 钱包 + 根 CA + 恶意节点抓捕 + E.3/E.4 现场核验三端输出完全一致 |

### 5.3 三端性能基准实测 (`wasm` / `js` / `native`)

实测命令：`moon bench -p CoolrfulDARkness/moonfrost/tests --target <wasm|js|native> --release -d`（均 `10 / 10 passed`，0 警告）。注：Windows 环境下 `native` 目标默认使用 MoonBit 内置轻量级 `tcc` 链接，因此 `wasm`（JIT 优化）在本机表现略快于 `native`；Linux/macOS 使用 `gcc`/`clang -O2` 时原生性能将进一步提升。

| 基准项 (`tests/frost_bench_test.mbt`) | `wasm` (`--release`) | `native` (`--release`, tcc) | `js` (`--release`, Node v22) |
| :--- | ---: | ---: | ---: |
| `bench_ristretto255_dkg_3of5`（5 节点全 3 轮 DKG） | `995.24 ms ± 6.99 ms` | `1.34 s ± 15.95 ms` | `3.32 s ± 41.93 ms` |
| `bench_ristretto255_commit`（Round 1 双承诺） | `9.72 ms ± 125.13 µs` | `12.91 ms ± 108.17 µs` | `32.46 ms ± 639.00 µs` |
| `bench_ristretto255_sign`（含 fresh commit + sign） | `29.59 ms ± 325.54 µs` | `40.52 ms ± 339.11 µs` | `100.29 ms ± 1.47 ms` |
| `bench_ristretto255_aggregate_3of5`（3-of-5 聚合+验签） | `28.39 ms ± 257.98 µs` | `38.87 ms ± 459.97 µs` | `97.96 ms ± 1.96 ms` |
| `bench_ristretto255_verify`（标准 Schnorr 验签） | `10.63 ms ± 67.67 µs` | `14.36 ms ± 97.77 µs` | `35.90 ms ± 700.47 µs` |
| `bench_p256_dkg_3of5`（5 节点全 3 轮 DKG） | `2.25 s ± 37.70 ms` | `3.43 s ± 23.31 ms` | `5.53 s ± 44.29 ms` |
| `bench_p256_commit`（Round 1 双承诺） | `22.74 ms ± 283.67 µs` | `33.46 ms ± 269.02 µs` | `73.37 ms ± 921.77 µs` |
| `bench_p256_sign`（含 fresh commit + sign） | `59.78 ms ± 666.75 µs` | `95.80 ms ± 1.22 ms` | `218.88 ms ± 5.82 ms` |
| `bench_p256_aggregate_3of5`（3-of-5 聚合+验签） | `59.28 ms ± 670.03 µs` | `93.12 ms ± 1.25 ms` | `207.39 ms ± 2.93 ms` |
| `bench_p256_verify`（标准 Schnorr 验签） | `23.98 ms ± 176.39 µs` | `38.92 ms ± 688.16 µs` | `77.44 ms ± 773.76 µs` |
