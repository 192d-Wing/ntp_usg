window.BENCHMARK_DATA = {
  "lastUpdate": 1771402555795,
  "repoUrl": "https://github.com/192d-Wing/ntp_usg",
  "entries": {
    "Selection Algorithm Benchmarks": [
      {
        "commit": {
          "author": {
            "email": "john.willman.1@us.af.mil",
            "name": "1456055067",
            "username": "1456055067"
          },
          "committer": {
            "email": "john.willman.1@us.af.mil",
            "name": "1456055067",
            "username": "1456055067"
          },
          "distinct": true,
          "id": "384fe7e1bd68394b28f32d4a57e14e92455c8282",
          "message": "fix: add safe.directory for benchmark action in container\n\nThe benchmark-action runs git fetch inside a container where the\nworkspace is owned by a different UID, triggering \"dubious ownership\".",
          "timestamp": "2026-02-17T09:32:15-06:00",
          "tree_id": "bdb20573b058c415d639da5225b171095f358361",
          "url": "https://github.com/192d-Wing/ntp_usg/commit/384fe7e1bd68394b28f32d4a57e14e92455c8282"
        },
        "date": 1771342577440,
        "tool": "cargo",
        "benches": [
          {
            "name": "select_truechimers/3",
            "value": 63,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/5",
            "value": 147,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/10",
            "value": 387,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/20",
            "value": 804,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/3",
            "value": 25,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/5",
            "value": 91,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/10",
            "value": 444,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/15",
            "value": 1207,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "combine/3",
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "combine/5",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "combine/10",
            "value": 50,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/5",
            "value": 384,
            "range": "± 231",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/10",
            "value": 997,
            "range": "± 558",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/20",
            "value": 2584,
            "range": "± 1371",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "f303ba1b4f024d645d29694db027538bdf980899",
          "message": "build(deps): update criterion from 0.5 to 0.8\n\nUpdates the requirements on [criterion](https://github.com/criterion-rs/criterion.rs) to permit the latest version.\n- [Release notes](https://github.com/criterion-rs/criterion.rs/releases)\n- [Changelog](https://github.com/criterion-rs/criterion.rs/blob/master/CHANGELOG.md)\n- [Commits](https://github.com/criterion-rs/criterion.rs/compare/0.5.0...criterion-v0.8.2)\n\n---\nupdated-dependencies:\n- dependency-name: criterion\n  dependency-version: 0.8.2\n  dependency-type: direct:production\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-02-17T13:04:58-06:00",
          "tree_id": "d9f85b22d9c0d49ca982612b3e21260e65f48cc1",
          "url": "https://github.com/192d-Wing/ntp_usg/commit/f303ba1b4f024d645d29694db027538bdf980899"
        },
        "date": 1771355329451,
        "tool": "cargo",
        "benches": [
          {
            "name": "select_truechimers/3",
            "value": 62,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/5",
            "value": 138,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/10",
            "value": 350,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/20",
            "value": 775,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/3",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/5",
            "value": 107,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/10",
            "value": 502,
            "range": "± 43",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/15",
            "value": 1359,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "combine/3",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "combine/5",
            "value": 35,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "combine/10",
            "value": 51,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/5",
            "value": 338,
            "range": "± 333",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/10",
            "value": 982,
            "range": "± 806",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/20",
            "value": 2757,
            "range": "± 2216",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "john.willman.1@us.af.mil",
            "name": "1456055067",
            "username": "1456055067"
          },
          "committer": {
            "email": "john.willman.1@us.af.mil",
            "name": "1456055067",
            "username": "1456055067"
          },
          "distinct": true,
          "id": "30d9b54013c678586af329e8a9abb0c906244248",
          "message": "feat: add post-quantum NTS and IPv6-first defaults\n\nEnable post-quantum key exchange (X25519MLKEM768) for NTS via the\n`pq-nts` feature flag, which is auto-enabled by `nts`/`nts-smol`.\nTLS 1.3 negotiation falls back to classical X25519 automatically.\n\nMake IPv6 the default address family for both client DNS resolution\nand server listen addresses. The `ipv4` feature restores the previous\nIPv4-only behavior. Add pre-commit hooks for tests and doc checks.",
          "timestamp": "2026-02-17T13:53:55-06:00",
          "tree_id": "7830657a3002d2f78a3bfd2d8d99a9f568e22c51",
          "url": "https://github.com/192d-Wing/ntp_usg/commit/30d9b54013c678586af329e8a9abb0c906244248"
        },
        "date": 1771359051266,
        "tool": "cargo",
        "benches": [
          {
            "name": "select_truechimers/3",
            "value": 62,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/5",
            "value": 139,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/10",
            "value": 351,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/20",
            "value": 777,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/3",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/5",
            "value": 107,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/10",
            "value": 504,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/15",
            "value": 1361,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "combine/3",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "combine/5",
            "value": 38,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "combine/10",
            "value": 51,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/5",
            "value": 343,
            "range": "± 326",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/10",
            "value": 1013,
            "range": "± 845",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/20",
            "value": 2812,
            "range": "± 1082",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "john.willman.1@us.af.mil",
            "name": "1456055067",
            "username": "1456055067"
          },
          "committer": {
            "email": "john.willman.1@us.af.mil",
            "name": "1456055067",
            "username": "1456055067"
          },
          "distinct": true,
          "id": "6b3d3ba7f47631f360f94dd9291c9a46116c0474",
          "message": "feat: add Roughtime protocol client with Ed25519 verification\n\nImplement Roughtime (draft-ietf-ntp-roughtime-15) as a feature-gated\nmodule providing authenticated coarse time with cryptographic proof of\nserver malfeasance. Uses ring for Ed25519 signatures and SHA-512 Merkle\ntree verification (zero new dependencies).\n\nProto crate: tag-value map wire codec, request builder, and full\nresponse verification pipeline. Client crate: sync + async (tokio) API\nwith base64 public key helper. Includes integration tests against\nCloudflare Roughtime and CI coverage on all platforms.",
          "timestamp": "2026-02-17T16:57:33-06:00",
          "tree_id": "596cc8cdd3d57689d36fb9f77c4415bbe5c3aff5",
          "url": "https://github.com/192d-Wing/ntp_usg/commit/6b3d3ba7f47631f360f94dd9291c9a46116c0474"
        },
        "date": 1771369377885,
        "tool": "cargo",
        "benches": [
          {
            "name": "select_truechimers/3",
            "value": 62,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/5",
            "value": 138,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/10",
            "value": 350,
            "range": "± 23",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/20",
            "value": 800,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/3",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/5",
            "value": 107,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/10",
            "value": 505,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/15",
            "value": 1359,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "combine/3",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "combine/5",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "combine/10",
            "value": 52,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/5",
            "value": 354,
            "range": "± 323",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/10",
            "value": 1050,
            "range": "± 858",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/20",
            "value": 2831,
            "range": "± 1064",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "john.willman.1@us.af.mil",
            "name": "1456055067",
            "username": "1456055067"
          },
          "committer": {
            "email": "john.willman.1@us.af.mil",
            "name": "1456055067",
            "username": "1456055067"
          },
          "distinct": true,
          "id": "ba71af50d323cadb199f6ba80f25ed3226debf32",
          "message": "chore: bump version to 4.0.0, mark NTPv5 complete, add ntpv5 CI step\n\n- Bump workspace version from 3.4.0 to 4.0.0\n- Update ROADMAP.md NTPv5 section with completion status\n- Add ntpv5 feature test step to CI for all platforms\n- Add ntpv5 to minimal-versions check",
          "timestamp": "2026-02-18T01:06:53-06:00",
          "tree_id": "512879de58778d7d7e069071d9eebf7c2be60479",
          "url": "https://github.com/192d-Wing/ntp_usg/commit/ba71af50d323cadb199f6ba80f25ed3226debf32"
        },
        "date": 1771398683978,
        "tool": "cargo",
        "benches": [
          {
            "name": "select_truechimers/3",
            "value": 62,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/5",
            "value": 139,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/10",
            "value": 361,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/20",
            "value": 803,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/3",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/5",
            "value": 107,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/10",
            "value": 509,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/15",
            "value": 1388,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "combine/3",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "combine/5",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "combine/10",
            "value": 56,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/5",
            "value": 336,
            "range": "± 287",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/10",
            "value": 1004,
            "range": "± 738",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/20",
            "value": 2804,
            "range": "± 1019",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "john.willman.1@us.af.mil",
            "name": "1456055067",
            "username": "1456055067"
          },
          "committer": {
            "email": "john.willman.1@us.af.mil",
            "name": "1456055067",
            "username": "1456055067"
          },
          "distinct": true,
          "id": "cfa64660f9ef934ad0490b8430d0c0cc24c147cd",
          "message": "fix: remove invalid --output-prefix flag from cargo cyclonedx\n\nThe flag does not exist in the installed version of cargo-cyclonedx,\ncausing the SBOM generation step (and all subsequent publish steps) to\nfail. Drop the flag; crate names already match the ntp_usg* glob used\nby the rename loop and release upload.",
          "timestamp": "2026-02-18T01:23:43-06:00",
          "tree_id": "fdb163e992634982e7c272b353e93f7f19c06141",
          "url": "https://github.com/192d-Wing/ntp_usg/commit/cfa64660f9ef934ad0490b8430d0c0cc24c147cd"
        },
        "date": 1771399655299,
        "tool": "cargo",
        "benches": [
          {
            "name": "select_truechimers/3",
            "value": 63,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/5",
            "value": 140,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/10",
            "value": 389,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/20",
            "value": 799,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/3",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/5",
            "value": 107,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/10",
            "value": 528,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/15",
            "value": 1407,
            "range": "± 88",
            "unit": "ns/iter"
          },
          {
            "name": "combine/3",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "combine/5",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "combine/10",
            "value": 52,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/5",
            "value": 341,
            "range": "± 324",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/10",
            "value": 1025,
            "range": "± 854",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/20",
            "value": 2810,
            "range": "± 1252",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "john.willman.1@us.af.mil",
            "name": "1456055067",
            "username": "1456055067"
          },
          "committer": {
            "email": "john.willman.1@us.af.mil",
            "name": "1456055067",
            "username": "1456055067"
          },
          "distinct": true,
          "id": "e48f418147115b7bad64ea6c6d59d325cb8637e1",
          "message": "feat: add WASM support with ntp_usg-wasm wrapper crate\n\nAdd wasm32-unknown-unknown compilation support for ntp_usg-proto and a\nnew ntp_usg-wasm crate providing JavaScript-friendly bindings via\nwasm-bindgen for browser packet inspection tools.\n\n- New ntp_usg-wasm crate: NtpPacket parser, timestamp conversion,\n  extension field parsing, client request builder (37 KB WASM binary)\n- CI wasm job: cargo check (4 feature combos) + wasm-pack build\n- Version::value() accessor on ntp_usg-proto for WASM wrapper use\n- ROADMAP §5 marked complete (WASI deferred)",
          "timestamp": "2026-02-18T01:54:56-06:00",
          "tree_id": "029ab5b7f0be18a9a549fd2fddeb9b5a93e31ca9",
          "url": "https://github.com/192d-Wing/ntp_usg/commit/e48f418147115b7bad64ea6c6d59d325cb8637e1"
        },
        "date": 1771401648866,
        "tool": "cargo",
        "benches": [
          {
            "name": "select_truechimers/3",
            "value": 62,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/5",
            "value": 141,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/10",
            "value": 354,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/20",
            "value": 804,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/3",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/5",
            "value": 106,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/10",
            "value": 495,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/15",
            "value": 1304,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "combine/3",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "combine/5",
            "value": 37,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "combine/10",
            "value": 51,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/5",
            "value": 343,
            "range": "± 306",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/10",
            "value": 976,
            "range": "± 743",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/20",
            "value": 2675,
            "range": "± 2131",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "john.willman.1@us.af.mil",
            "name": "1456055067",
            "username": "1456055067"
          },
          "committer": {
            "email": "john.willman.1@us.af.mil",
            "name": "1456055067",
            "username": "1456055067"
          },
          "distinct": true,
          "id": "7d9c7322b22cfa86d1e1c8f60de0a540a05f9b00",
          "message": "fix: skip network tests on unreachable/no-route errors\n\nThe NIST network tests panicked on arm64 CI runners where the network\nwas unreachable (os error 101). Extend the skip condition to cover\nENETUNREACH, EHOSTUNREACH, ConnectionRefused, ConnectionReset, and\nAddrNotAvailable in addition to the existing TimedOut/WouldBlock.",
          "timestamp": "2026-02-18T02:01:03-06:00",
          "tree_id": "82c69b8019ccce013477950b32cd90757f884e8f",
          "url": "https://github.com/192d-Wing/ntp_usg/commit/7d9c7322b22cfa86d1e1c8f60de0a540a05f9b00"
        },
        "date": 1771401965151,
        "tool": "cargo",
        "benches": [
          {
            "name": "select_truechimers/3",
            "value": 65,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/5",
            "value": 139,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/10",
            "value": 343,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/20",
            "value": 795,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/3",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/5",
            "value": 106,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/10",
            "value": 495,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/15",
            "value": 1304,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "combine/3",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "combine/5",
            "value": 37,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "combine/10",
            "value": 51,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/5",
            "value": 345,
            "range": "± 340",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/10",
            "value": 990,
            "range": "± 604",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/20",
            "value": 2663,
            "range": "± 1578",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "john.willman.1@us.af.mil",
            "name": "1456055067",
            "username": "1456055067"
          },
          "committer": {
            "email": "john.willman.1@us.af.mil",
            "name": "1456055067",
            "username": "1456055067"
          },
          "distinct": true,
          "id": "c2b7ccf6e4c76951538ee3aa9944d5437f60c4aa",
          "message": "fix: use shared network error helper across all integration tests\n\nThe previous fix (7d9c732) only covered unit tests in request.rs and\nsntp.rs.  The async integration tests in tests/async_ntp.rs still\npanicked on ENETUNREACH, causing CI failures on Linux x64.\n\nExtract a common::is_network_skip_error() helper into\ntests/common/mod.rs and use it in all 5 integration test files:\nasync_ntp, integration, smol_ntp, roughtime, nts_integration.",
          "timestamp": "2026-02-18T02:11:34-06:00",
          "tree_id": "5ea453269ae011189266989197c848639f2c828c",
          "url": "https://github.com/192d-Wing/ntp_usg/commit/c2b7ccf6e4c76951538ee3aa9944d5437f60c4aa"
        },
        "date": 1771402555188,
        "tool": "cargo",
        "benches": [
          {
            "name": "select_truechimers/3",
            "value": 56,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/5",
            "value": 144,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/10",
            "value": 356,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/20",
            "value": 763,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/3",
            "value": 25,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/5",
            "value": 93,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/10",
            "value": 435,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/15",
            "value": 1188,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "combine/3",
            "value": 28,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "combine/5",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "combine/10",
            "value": 47,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/5",
            "value": 371,
            "range": "± 215",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/10",
            "value": 955,
            "range": "± 482",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/20",
            "value": 2568,
            "range": "± 1303",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}