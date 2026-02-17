window.BENCHMARK_DATA = {
  "lastUpdate": 1771342578323,
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
      }
    ]
  }
}