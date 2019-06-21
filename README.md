VMA extractor
=============

`vma.py` implements a VMA extraction tool in Python 3.

Usage:
```sh
./vma.py path/to/source.vma path/to/target/directory
```

I think it is pretty important to be able to read Proxmox backups outside of a
Proxmox environment. Yet, porting their VMA implementation to a standalone
tool proved difficult. VMA-Reader and VMA-Writer are implemented as patches to
the Proxmox-patched version and Qemu and are thus very difficult to compile on
non-Proxmox systems.
