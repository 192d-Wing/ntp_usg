window.BENCHMARK_DATA = {
  "lastUpdate": 1771355329899,
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
      }
    ]
  }
}