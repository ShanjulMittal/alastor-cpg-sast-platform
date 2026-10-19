"""
Hidden gadgets module containing dormant zero-day gadgets.
"""
import subprocess


def legacy_debug_shell(cmd):
    """
    Dormant zero-day gadget: never imported or called anywhere in the repository.
    Triggers Rule 2 (Orphaned Functions & Dormant Zero-Day Gadgets).
    """
    return subprocess.Popen(cmd, shell=True)
