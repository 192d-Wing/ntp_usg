window.BENCHMARK_DATA = {
  "lastUpdate": 1771474471033,
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
          "id": "79b63809a11e0e5e49afb8fee9eceeda980808c0",
          "message": "ci: cache Miri sysroot and limit proptest cases under Miri\n\n- Add cache-directories: ~/.cache/miri to Swatinem/rust-cache so the\n  Miri sysroot (pre-built std) is persisted across runs instead of being\n  rebuilt from source every time.\n- Set PROPTEST_CASES=1 in the Miri job env to avoid running 256\n  interpreted iterations per proptest test; 1 case still exercises every\n  code path under Miri.",
          "timestamp": "2026-02-18T02:33:46-06:00",
          "tree_id": "e213e78105b009f1bc9490fdee6b14597446e235",
          "url": "https://github.com/192d-Wing/ntp_usg/commit/79b63809a11e0e5e49afb8fee9eceeda980808c0"
        },
        "date": 1771403859779,
        "tool": "cargo",
        "benches": [
          {
            "name": "select_truechimers/3",
            "value": 64,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/5",
            "value": 140,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/10",
            "value": 380,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/20",
            "value": 787,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/3",
            "value": 21,
            "range": "± 1",
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
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/15",
            "value": 1305,
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
            "value": 342,
            "range": "± 305",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/10",
            "value": 979,
            "range": "± 761",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/20",
            "value": 2674,
            "range": "± 1971",
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
          "id": "02fd5449a6c96e01d5e40e79f76f4cbd0ac7a177",
          "message": "chore: add WASM crate to publish pipeline and write v4.0.0 changelog\n\n- Add ntp_usg-wasm to the crates.io publish workflow (after server)\n- Add publishing metadata (docs.rs, readme, keywords, categories)\n- Write comprehensive CHANGELOG entry for v4.0.0 covering Roughtime,\n  PQ-NTS, IPv6 optimizations, NTPv5, and WASM support",
          "timestamp": "2026-02-18T02:53:15-06:00",
          "tree_id": "3e7c019b30ab510dfc50aadc8855b4b7635db055",
          "url": "https://github.com/192d-Wing/ntp_usg/commit/02fd5449a6c96e01d5e40e79f76f4cbd0ac7a177"
        },
        "date": 1771405031148,
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
            "value": 140,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/10",
            "value": 380,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/20",
            "value": 797,
            "range": "± 15",
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
            "value": 1303,
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
            "value": 342,
            "range": "± 321",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/10",
            "value": 1006,
            "range": "± 857",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/20",
            "value": 2684,
            "range": "± 2160",
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
          "id": "57c838a93adaa983f753af8854bb97ed5037df7d",
          "message": "chore: updated badges",
          "timestamp": "2026-02-18T02:53:45-06:00",
          "tree_id": "4d72a724d644773dae3aa3fbc3c633a534f2874c",
          "url": "https://github.com/192d-Wing/ntp_usg/commit/57c838a93adaa983f753af8854bb97ed5037df7d"
        },
        "date": 1771405092405,
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
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/10",
            "value": 358,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/20",
            "value": 797,
            "range": "± 4",
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
            "value": 496,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/15",
            "value": 1313,
            "range": "± 7",
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
            "value": 346,
            "range": "± 310",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/10",
            "value": 1004,
            "range": "± 801",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/20",
            "value": 2676,
            "range": "± 1925",
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
          "id": "77cb264e719567f32054a82a8e1ed8103e2edb21",
          "message": "fix: install cargo-cyclonedx and collect SBOMs from crate subdirectories\n\ncargo-cyclonedx writes output files into each crate directory, not the\nworkspace root. Add an install step and collect files into sbom/ for\nthe GitHub Release upload.",
          "timestamp": "2026-02-18T03:01:40-06:00",
          "tree_id": "6ce391bfc1bd031ab7bcd857a120a928a4fe9eca",
          "url": "https://github.com/192d-Wing/ntp_usg/commit/77cb264e719567f32054a82a8e1ed8103e2edb21"
        },
        "date": 1771405559657,
        "tool": "cargo",
        "benches": [
          {
            "name": "select_truechimers/3",
            "value": 64,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/5",
            "value": 140,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/10",
            "value": 381,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/20",
            "value": 794,
            "range": "± 10",
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
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/15",
            "value": 1303,
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
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/5",
            "value": 347,
            "range": "± 308",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/10",
            "value": 1008,
            "range": "± 802",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/20",
            "value": 2677,
            "range": "± 2199",
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
          "id": "1fd74ed23511263946c8b5d173e1845b8d432e78",
          "message": "fix: clean up SBOM files from crate dirs before cargo publish\n\ncargo-cyclonedx leaves .cdx.json files in crate directories, causing\ncargo publish to fail with \"uncommitted changes\" error.",
          "timestamp": "2026-02-18T03:09:16-06:00",
          "tree_id": "c3896415c2d223448d4709e6c524dc1884408dab",
          "url": "https://github.com/192d-Wing/ntp_usg/commit/1fd74ed23511263946c8b5d173e1845b8d432e78"
        },
        "date": 1771405989808,
        "tool": "cargo",
        "benches": [
          {
            "name": "select_truechimers/3",
            "value": 64,
            "range": "± 0",
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
            "value": 379,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/20",
            "value": 803,
            "range": "± 2",
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
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/10",
            "value": 496,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/15",
            "value": 1306,
            "range": "± 3",
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
            "value": 346,
            "range": "± 361",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/10",
            "value": 1004,
            "range": "± 818",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/20",
            "value": 2700,
            "range": "± 2307",
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
          "id": "46135d2e79287bab014db6f2217a18c83bc83ed0",
          "message": "chore: bump version to 4.0.1 for release\n\nv4.0.0 tag is locked by repository rules. Bumping to 4.0.1 with\npublish pipeline fixes (SBOM collection, WASM crate publishing).",
          "timestamp": "2026-02-18T03:10:42-06:00",
          "tree_id": "dba371b37227688e8f78b95d72286b2a9716a40b",
          "url": "https://github.com/192d-Wing/ntp_usg/commit/46135d2e79287bab014db6f2217a18c83bc83ed0"
        },
        "date": 1771406153063,
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
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/10",
            "value": 369,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/20",
            "value": 798,
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
            "value": 108,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/10",
            "value": 510,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/15",
            "value": 1389,
            "range": "± 2",
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
            "value": 50,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/5",
            "value": 328,
            "range": "± 298",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/10",
            "value": 987,
            "range": "± 759",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/20",
            "value": 2807,
            "range": "± 1029",
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
          "id": "42add7307b18c2372ab650f2be58b7687dbac64b",
          "message": "feat: release v4.1.0 — server improvements and API polish\n\nAdd runtime metrics (ServerMetrics with AtomicU64 counters), runtime\nconfiguration (ConfigHandle for live access control/rate limit updates),\n12 server integration tests, Default/Eq/Hash trait derives on core types,\nVersion::new() constructor, WASM setters + computeOffsetDelay +\nvalidateResponse, feature flag documentation, and Packet::default()\nsimplification.",
          "timestamp": "2026-02-18T10:46:35-06:00",
          "tree_id": "9ff7dbeb4ef1a08563fb2f95ab877a2749a96c50",
          "url": "https://github.com/192d-Wing/ntp_usg/commit/42add7307b18c2372ab650f2be58b7687dbac64b"
        },
        "date": 1771433460984,
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
            "value": 135,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/10",
            "value": 334,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/20",
            "value": 751,
            "range": "± 5",
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
            "value": 512,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/15",
            "value": 1388,
            "range": "± 7",
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
            "value": 51,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/5",
            "value": 327,
            "range": "± 328",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/10",
            "value": 977,
            "range": "± 767",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/20",
            "value": 2776,
            "range": "± 2120",
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
          "id": "6457d726c6cc63fb992b83c8f1cd22eebfd21477",
          "message": "feat: release v4.3.0 — hardening (tests, benchmarks, safety)\n\n75 new unit tests across 4 previously untested modules, 9 criterion\nbenchmarks (parsing + server throughput), SAFETY comments on all 16\nunsafe blocks, Instant::new() panic converted to Result, 7 new CI\nfeature combination tests, and docs/FEATURE_FLAGS.md + PLATFORM_SUPPORT.md.",
          "timestamp": "2026-02-18T14:54:47-06:00",
          "tree_id": "024172555be1fb207cdaba0a42b3c1e5509bd3eb",
          "url": "https://github.com/192d-Wing/ntp_usg/commit/6457d726c6cc63fb992b83c8f1cd22eebfd21477"
        },
        "date": 1771448863967,
        "tool": "cargo",
        "benches": [
          {
            "name": "select_truechimers/3",
            "value": 61,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/5",
            "value": 143,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/10",
            "value": 341,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/20",
            "value": 771,
            "range": "± 4",
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
            "value": 109,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/10",
            "value": 498,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/15",
            "value": 1318,
            "range": "± 5",
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
            "range": "± 325",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/10",
            "value": 981,
            "range": "± 853",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/20",
            "value": 2713,
            "range": "± 2235",
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
          "id": "494ac5dd0f94cd7b19fb6a5a6ce15c322aabb8cc",
          "message": "chore: bump version to 4.4.0\n\nAdd 62 unit tests across protocol/io.rs, protocol/bytes.rs, and\nnts_common.rs. Upgrade socket2 0.5→0.6 (set_tos→set_tos_v4/set_tclass_v6).\nRemove dead_code allows on NTS server public API. Replace .parse().unwrap()\nwith const constructors for broadcast/multicast addresses.",
          "timestamp": "2026-02-18T16:57:39-06:00",
          "tree_id": "6aa4fc1cea58d37763996f33d84939a9829b6f6f",
          "url": "https://github.com/192d-Wing/ntp_usg/commit/494ac5dd0f94cd7b19fb6a5a6ce15c322aabb8cc"
        },
        "date": 1771456085086,
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
            "value": 137,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/10",
            "value": 360,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/20",
            "value": 779,
            "range": "± 2",
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
            "value": 108,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/10",
            "value": 488,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/15",
            "value": 1228,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "combine/3",
            "value": 30,
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
            "value": 335,
            "range": "± 318",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/10",
            "value": 983,
            "range": "± 817",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/20",
            "value": 2629,
            "range": "± 2164",
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
          "id": "61bc8c094910043070db35b775a54404d9fb891e",
          "message": "refactor: deduplicate tokio/smol code, bump to v4.7.0\n\nExtract shared logic from 4 pairs of near-identical tokio/smol files\ninto common modules, eliminating ~1,300 lines of duplication:\n\n- Server builder → define_server_builder! macro in server_common/builder.rs\n- NTS-KE server → nts_ke_server_common.rs\n- Client builder → define_client_builder! macro in client_common.rs\n- NTS client → nts_ke_exchange.rs",
          "timestamp": "2026-02-18T22:10:12-06:00",
          "tree_id": "5e05a017578fc73d48df66a5fb6cd4650a2a400b",
          "url": "https://github.com/192d-Wing/ntp_usg/commit/61bc8c094910043070db35b775a54404d9fb891e"
        },
        "date": 1771474470247,
        "tool": "cargo",
        "benches": [
          {
            "name": "select_truechimers/3",
            "value": 61,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/5",
            "value": 160,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/10",
            "value": 347,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "select_truechimers/20",
            "value": 793,
            "range": "± 4",
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
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/10",
            "value": 489,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "cluster_survivors/15",
            "value": 1283,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "combine/3",
            "value": 30,
            "range": "± 1",
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
            "value": 334,
            "range": "± 282",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/10",
            "value": 999,
            "range": "± 756",
            "unit": "ns/iter"
          },
          {
            "name": "full_selection_pipeline/20",
            "value": 2729,
            "range": "± 1951",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}