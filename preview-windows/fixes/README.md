# Issue #347: explicit workspace boundary

The preview CLI requires --workspace but replaced it with an ancestor found by
discover_project. Keep the explicit root for CLI operations. Hook discovery is
unchanged: after setup its existing activation/storage marker identifies this
root, including calls from a child directory, without inheriting an independent
nested repository.

Validate every requested source with the existing content-free protect-plan
validation before setup writes DB, configuration, activation, or ignore entries.
This prevents predictable missing/outside/directory source failures from leaving
partial setup. This is not a transaction rollback for concurrent deletion, disk
failure, or arbitrary installer errors.

## Reproduction and validation

- Original Mac 20261108.6: new check_workspace.py reproduces source_not_found,
  with workspace_root incorrectly pointing at the parent.
- Patched Mac: both ancestor Git and already-configured ancestor cases pass.
  Checks cover repeated setup, registered source, unchanged ancestor bytes,
  nested SessionStart recorded under the explicit root, nested repository
  isolation and failed registration leaving no setup files.
- check_mac_install.py passes the actual Mac installer and generated Hook
  command, plus a missing-source installation with no writes.
- Windows native execution is pending. smoke.py now installs under an ancestor
  .git, checks the ancestor remains untouched, then runs the same regression.
  Windows locking is platform-specific; Mac results do not substitute for Windows.

## Rebuild

Copy an unpacked original kit, then:
python preview-windows/fixes/workspace_347.py /path/to/copied-kit

This verifies the input runtime manifest, patches the shared app.py, and updates
its hash. runtime.patch is the reviewable source diff for both platforms.
The original archives and installed runtimes are unchanged.
The Windows 20261119.1 ZIP is the patched 20261108.1 kit; SHA256SUMS identifies it.
No release assets have been uploaded.
