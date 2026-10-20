# Wutong CLI · 梧桐命令行

[![CI](https://github.com/project-wutong/wutong-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/project-wutong/wutong-cli/actions/workflows/ci.yml)
Rust 2024 · `AGPL-3.0-only`

## 中文

`wutong` 是梧桐套件的 Rust 命令行工具，**默认完全本地运行**（无需账户、网络、Server 或 AI）：
文件字节摘要、信封严格校验（JSON + Schema + 语义）、JCS/dCBOR 规范化、Ed25519 验签。
后续将加入最小补丁应用、索引构建以及对 `wutong-networkd` / `wutong-server` 的可选调用。

```bash
cargo install --git https://github.com/project-wutong/wutong-cli
wutong validate message.json
wutong canon --encoding dcbor message.json
wutong verify --public-key <hex> signed.json
wutong digest notes/demo.md
```

## English

Local-first command line for the Wutong Protocol built on [`wutong-core`](https://github.com/project-wutong/wutong-core).
All commands work offline; remote commands are opt-in and planned.
