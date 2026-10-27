"""ATTACK side of BaitWatch: test repos, obfuscation and decoders.

Owned by Aditya (Shellghostt).  Nothing in this package ever ships as a
detector: it exists so the product can be attacked on purpose, and so the READ
side has a symmetric transform table to decode what it finds.

Layout::

    attacks/synth/     encoders + file-voice templates (training data, repos)
    attacks/decoders.py  external decoder plugin loaded by read.scan()
    attacks/repos/     five attack repositories, each with MANIFEST.json
    attacks/examples/  two hand-written examples per threat type
    attacks/lint.py    the safety lint that keeps CI honest
    attacks/harness.py the per-repo detection table (regression suite)
"""

__all__ = ["__version__"]

__version__ = "0.1.0"
