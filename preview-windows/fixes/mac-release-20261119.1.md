# Mac release 20261119.1
Based on tester-20261108.6. Apply workspace_347.py, replace update.py with
mac-update-20261119.1.py, include the original .6 runtime-manifest as
supported-20261108.6.json alongside the existing .5 manifest.
Set runtime/tooluseproxy/release_check.py VERSION to 20261119.1 and update its
manifest SHA256. Update top-level Markdown release links to tester-20261119.1.
Exclude __pycache__ when packaging.

Final ZIP SHA256: 54368b3a04ba1dd4a16f5946c9c5f84638cd22716dbe83adf5a562473e5d3d80
