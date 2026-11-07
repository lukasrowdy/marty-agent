"""Prepare and verify an ACL-private data directory for Jr's own identity.

This is staged for a future distinct Windows service account. Run it from
that account before storing the Jr passphrase verifier or DPAPI history.
It never changes Marty's directories or the VM.
"""

from __future__ import annotations

from pathlib import Path

import jr_deps

# CHANGED 2026-09-28 (Jr overnight build, item 3 "app"): the bundled pywin32 is found through
# jr_deps.load() (honours JR_DEPS_DIR, then .deps beside the module), replacing the inline
# .deps block so every module resolves the dependency the same way.
jr_deps.load()

import win32api
import win32con
import win32security
import ntsecuritycon


SYSTEM = "S-1-5-18"
ADMINS = "S-1-5-32-544"
INHERIT = win32con.CONTAINER_INHERIT_ACE | win32con.OBJECT_INHERIT_ACE


class PrivateRootError(Exception):
    pass


def current_sid() -> str:
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    return win32security.ConvertSidToStringSid(
        win32security.GetTokenInformation(token, win32security.TokenUser)[0])


def _sid(value: str):
    return win32security.ConvertStringSidToSid(value)


def _descriptor(path: Path):
    return win32security.GetNamedSecurityInfo(
        str(path), win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION |
        win32security.DACL_SECURITY_INFORMATION)


def verify_private_root(path: Path, *, expected_sid: str | None = None) -> None:
    """Fail closed unless owner and every access ACE match Jr's private ACL."""
    path = Path(path)
    if not path.is_dir() or path.is_symlink():
        raise PrivateRootError("Jr data root is missing or redirected")
    wanted = expected_sid or current_sid()
    descriptor = _descriptor(path)
    owner = win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner())
    if owner != wanted:
        raise PrivateRootError("Jr data root is not owned by its service identity")
    if not descriptor.GetSecurityDescriptorControl()[0] & win32security.SE_DACL_PROTECTED:
        raise PrivateRootError("Jr data root inherits access from its parent")
    acl = descriptor.GetSecurityDescriptorDacl()
    if acl is None or acl.GetAceCount() != 3:
        raise PrivateRootError("Jr data root has an unexpected access list")
    seen = set()
    for index in range(acl.GetAceCount()):
        ace = acl.GetAce(index)
        ace_type, flags = ace[0]
        mask, sid = ace[1], ace[2]
        name = win32security.ConvertSidToStringSid(sid)
        if (ace_type != win32security.ACCESS_ALLOWED_ACE_TYPE or
            flags != INHERIT or mask != ntsecuritycon.FILE_ALL_ACCESS or
            name not in {SYSTEM, ADMINS, wanted} or name in seen):
            raise PrivateRootError("Jr data root grants unexpected access")
        seen.add(name)
    if seen != {SYSTEM, ADMINS, wanted}:
        raise PrivateRootError("Jr data root is missing a required identity")


def create_private_root(path: Path) -> None:
    """Create only a new empty root; never rewrite an existing data tree."""
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise PrivateRootError("Jr data root already exists; inspect it before provisioning")
    path.mkdir(parents=True, exist_ok=False)
    if path.is_symlink():
        raise PrivateRootError("Jr data root was redirected during creation")
    owner = current_sid()
    acl = win32security.ACL()
    for value in (SYSTEM, ADMINS, owner):
        acl.AddAccessAllowedAceEx(win32security.ACL_REVISION, INHERIT,
                                  ntsecuritycon.FILE_ALL_ACCESS, _sid(value))
    win32security.SetNamedSecurityInfo(
        str(path), win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION |
        win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        None, None, acl, None)
    verify_private_root(path, expected_sid=owner)
