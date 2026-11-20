# Design: zone process tracking (issue #154)

Status: proposed, 2026-11-20. Fixes
[edera-dev/falco_plugin#154](https://github.com/edera-dev/falco_plugin/issues/154).

## Problem

Zone `open` events reached Falco with `fd.name=NA`, `proc.exe=NA` and
`evt.res=<NA>`. Events from processes started after the zone snapshot were
logged as `no thread found ... dropping event`. No file rule on `edera_zone`
could fire.

## Root cause

Captured on a Xen worker (Edera 1.13.1, Falco 0.45.2) with a diagnostic build:

1. Every zone syscall event arrives with `event_category = "EC_TRACEPOINT"`.
2. `parsers::has_retval()` required `SYSCALL` or `EC_METAEVENT` in that string,
   so it returned false for every event, even though the return value was
   present (`retval=3` on the `/etc/shadow` open).
3. Every handler then treated the syscall as failed. Clone and fork children,
   including the child-side events that did arrive, were never added. `execve`
   never set the process; `open` never recorded the fd. The thread table stayed
   at its snapshot size (25 entries).

The wrong label comes from the zone. protect
`crates/libscap-rs/src/wrapper/scap/mod.rs` formats `ppm_event_info.category`
with `{:?}`. The value is a C bit set (`EC_FILE | EC_SYSCALL`), but
libscap-bindings types it as a Rust enum, so a combined value is not a valid
variant and prints as a wrong name.

## Changes

### 1. Return values come from the event, not the category string

`has_retval()` is true for any exit event with parameters, except
`PPME_GENERIC_X`. libsinsp also checks the category bits from its static event
table. Every exit event libscap defines is a syscall or metaevent exit whose
first parameter is the return value, so the result is the same. The plugin is
built without libscap's event table (`default-features = false`), so it can't
check the bits itself, and the zone's string can't be trusted.

### 2. Zones send process exits

With the return-value fix, every new process is added. A thread leaves the
table only on a process-exit event, and the zone's default syscall set has
none. So the table would grow for as long as Falco runs, and stale entries
would mislabel reused PIDs.

The plugin now sends an explicit set instead of an empty request (empty means
"zone default"): the zone default set plus `PPM_SC_SCHED_PROCESS_EXIT`. In
mirror mode it adds process exit to the set read from Falco, and if that map
can't be read it falls back to the same explicit set. The
copy matches protect `crates/zone/src/kernel_events.rs` in v1.13.1, v1.13.2 and
v1.13.4. This works with zones already deployed, without a protect release.

Trade-off: the plugin now carries a copy of the zone's default set, and the
copy can drift. Before, the plugin asked for "the default", so Falco users got
whatever protect's default said. From now on, if a future zone default adds or
removes events, Falco users won't see that change until someone updates the
plugin's copy. A unit test fences only the process-lifecycle events in the set,
not the full list.

Plan to remove the copy:

1. protect adds `PPM_SC_SCHED_PROCESS_EXIT` to the zone default set
   ([edera-dev/protect#5079](https://github.com/edera-dev/protect/pull/5079)).
2. Once every supported zone version includes it, the plugin goes back to
   sending an empty request ("zone default") and drops its copy.

Until then, whoever changes protect's zone default should update
`default_zone_syscalls()` in `src/source_plugin/client/enabled_syscalls.rs`.

### 3. Children move to the reaper on exit

`parse_thread_exit()` meant to reparent the exiting thread's children, but it
compared each thread's `ptid` with its own `tid`, so nothing moved. The next
purge then deleted running children whose parent had exited. This code never
ran before because no exit events arrived. It now matches libsinsp: children
of the exiting thread get the event's reaper tid, or no parent.

## Not changed

- **Mirror mode sends the wrong syscall set** ([#165](https://github.com/edera-dev/falco_plugin/issues/165), separate PR). With
  `mirror_host_syscalls: true` (the repo's Helm example,
  `examples/falco-helm-values.yaml`), the plugin reads Falco's
  `interesting_syscalls_table_64bit` map as libscap `ppm_sc` codes. That map is
  indexed by the kernel's syscall number, so zones get the wrong set. Fixing it
  needs the syscall-number to `ppm_sc` table. This change only makes sure mirror
  mode, and its fallback when the map can't be read, also ask for process exit.
  Falco's map never holds tracepoints, so mirror mode would otherwise reintroduce
  the unbounded thread table.
- **`evt.category` and `evt.count.error.memory`** still show the zone's wrong
  string until zones send correct categories (protect fix below).
- **Lost exit events** (ring-buffer drops) still leave entries behind. libsinsp
  covers this with periodic `/proc` rescans; the zone snapshot on reconnect is
  the nearest equivalent here. The soak test measures whether it matters.

## protect changes (separate PRs)

- [edera-dev/protect#5078](https://github.com/edera-dev/protect/pull/5078),
  `fix(libscap-rs): send syscall event category and flags as bit sets`, reads
  the raw bits and formats them as libscap writes them (`EC_FILE | EC_SYSCALL`).
  It fixes `evt.category` for new zones.
- [edera-dev/protect#5079](https://github.com/edera-dev/protect/pull/5079),
  `fix(zone): include process exit in the default syscall set`, adds
  `PPM_SC_SCHED_PROCESS_EXIT` to the zone default, which removes the need for
  the plugin's copy (see the plan above).

This plugin change does not depend on either one.

## Verification

- Unit tests (61 pass): return values with any category string; a replay of the
  captured sequence (fork child in a PID namespace, `execve cat`, `open
  /etc/shadow`); exited children leaving the table; running children surviving
  their parent. The replay and reparent tests fail on the old code.
- Before release, on one Xen worker:
  1. Stress test, about 30 minutes: about 1,000 short-lived processes per
     minute in an Edera pod. Pass: process-exit events arrive, and the table
     stays near the live process count.
  2. PID reuse: run enough processes to reuse PIDs. Pass: Falco reports the new
     program's name.
  3. 24-hour soak with normal workload. Pass: Falco memory is flat after
     warm-up, and the `/etc/shadow` rule fires with the right file and
     program.
