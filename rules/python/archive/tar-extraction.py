import contextlib
import os
import shutil
import sys
import tarfile
import tarfile as tf
import zipfile
from tarfile import TarFile, data_filter, fully_trusted_filter, tar_filter

import py7zr

DATA = "data"
TRUSTED = "fully_trusted"


VENDOR_TAR = tarfile.open("vendor/bundle.tar")
FONTS_TAR = tarfile.TarFile("vendor/fonts.tar")
ICONS_TAR = tarfile.TarFile.taropen("vendor/icons.tar")


# No filter, or filter=None: Python 3.13 and older extract with the fully_trusted behaviour
# (absolute names, ".." components and links outside the directory are honoured); only 3.14
# made "data" the default.
def unpack_release(archive_path, dest):
    tar = tarfile.open(archive_path)
    # ruleid: python.tar-extraction
    tar.extractall(dest)
    tar.close()


def unpack_with(archive_path, dest):
    with tarfile.open(archive_path, "r:gz") as tar:
        # ruleid: python.tar-extraction
        tar.extractall(path=dest)


def unpack_inline(archive_path, dest):
    # ruleid: python.tar-extraction
    tarfile.open(archive_path).extractall(dest)


def unpack_none(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        # ruleid: python.tar-extraction
        tar.extractall(dest, filter=None)


def unpack_numeric(fileobj, dest):
    tar = tarfile.open(fileobj=fileobj, mode="r|*")
    # ruleid: python.tar-extraction
    tar.extractall(dest, numeric_owner=True)


def unpack_class(archive_path, dest):
    tar = tarfile.TarFile(archive_path)
    # ruleid: python.tar-extraction
    tar.extractall(dest)


def unpack_classmethod(archive_path, dest):
    with tarfile.TarFile.gzopen(archive_path) as tar:
        # ruleid: python.tar-extraction
        tar.extractall(dest)


def unpack_imported(archive_path, dest):
    with TarFile.open(archive_path) as tar:
        # ruleid: python.tar-extraction
        tar.extractall(dest)


def unpack_alias(archive_path, dest):
    with tf.open(archive_path) as tar:
        # ruleid: python.tar-extraction
        tar.extractall(dest)


def unpack_two_items(archive_path, dest):
    with open(archive_path, "rb") as fh, tarfile.open(fileobj=fh) as tar:
        # ruleid: python.tar-extraction
        tar.extractall(dest)


def unpack_retry(archive_path, dest):
    try:
        tar = tarfile.open(archive_path, mode="r:gz")
    except tarfile.ReadError:
        tar = tarfile.open(archive_path, mode="r:bz2")
    if sys.version_info >= (3, 12):
        # ruleid: python.tar-extraction
        tar.extractall(dest, filter="fully_trusted")
    else:
        # ruleid: python.tar-extraction
        tar.extractall(dest)
    tar.close()


def unpack_retry_class(archive_path, dest, compressed):
    if compressed:
        tar = tarfile.TarFile.gzopen(archive_path)
    else:
        tar = tarfile.TarFile(archive_path)
    # ruleid: python.tar-extraction
    tar.extractall(dest)


def unpack_try_class(archive_path, dest):
    try:
        tar = tarfile.TarFile(archive_path)
    except tarfile.ReadError:
        return
    # ruleid: python.tar-extraction
    tar.extractall(dest)


def unpack_try_classmethod(archive_path, dest):
    try:
        tar = tarfile.TarFile.bz2open(archive_path)
    except tarfile.ReadError:
        return
    # ruleid: python.tar-extraction
    tar.extractall(dest)


def unpack_with_class(archive_path, dest):
    with tarfile.TarFile(archive_path) as tar:
        # ruleid: python.tar-extraction
        tar.extractall(dest)


def unpack_inline_class(archive_path, dest):
    # ruleid: python.tar-extraction
    tarfile.TarFile(archive_path).extractall(dest)
    # ruleid: python.tar-extraction
    tarfile.TarFile.taropen(archive_path).extractall(dest)


def install_vendor(dest):
    # ruleid: python.tar-extraction
    VENDOR_TAR.extractall(dest)
    # ruleid: python.tar-extraction
    FONTS_TAR.extractall(dest)
    # ruleid: python.tar-extraction
    ICONS_TAR.extractall(dest)


def unpack_closing(archive_path, dest):
    with contextlib.closing(tarfile.open(archive_path)) as tar:
        # ruleid: python.tar-extraction
        tar.extractall(dest)


def unpack_typed(tar: tarfile.TarFile, dest):
    # ruleid: python.tar-extraction
    tar.extractall(dest)


def unpack_typed_imported(tar: TarFile, dest):
    # ruleid: python.tar-extraction
    tar.extractall(dest)


# filter="fully_trusted" and its function honour every piece of metadata in the archive, as does
# a filter that returns each member unchanged.
def unpack_trusted(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        # ruleid: python.tar-extraction
        tar.extractall(dest, filter="fully_trusted")


def unpack_trusted_constant(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        # ruleid: python.tar-extraction
        tar.extractall(dest, filter=TRUSTED)


def unpack_trusted_function(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        # ruleid: python.tar-extraction
        tar.extractall(dest, filter=tarfile.fully_trusted_filter)


def unpack_trusted_imported(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        # ruleid: python.tar-extraction
        tar.extractall(dest, filter=fully_trusted_filter)


def unpack_identity(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        # ruleid: python.tar-extraction
        tar.extractall(dest, filter=lambda member, path: member)


# extract(): one member, the same filter argument.
def unpack_members(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            # ruleid: python.tar-extraction
            tar.extract(member, dest)


def unpack_iterated(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        for member in tar:
            if member.isfile():
                # ruleid: python.tar-extraction
                tar.extract(member, path=dest, set_attrs=False)


def unpack_one(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        # ruleid: python.tar-extraction
        tar.extract("config/settings.ini", dest, filter="fully_trusted")


# The instance's default filter (extraction_filter) set to the fully_trusted behaviour.
def unpack_default_trusted(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        tar.extraction_filter = tarfile.fully_trusted_filter
        # ruleid: python.tar-extraction
        tar.extractall(dest)


def unpack_default_identity(archive_path, dest):
    tar = tarfile.open(archive_path)
    tar.extraction_filter = lambda member, path: member
    # ruleid: python.tar-extraction
    tar.extractall(dest)


def unpack_default_none(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        tar.extraction_filter = None
        # ruleid: python.tar-extraction
        tar.extractall(dest)


def unpack_default_overridden(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        tar.extraction_filter = tarfile.fully_trusted_filter
        # ok: python.tar-extraction
        tar.extractall(dest, filter="data")


# The docs' getattr fallback: data where Python has filters, the fully_trusted behaviour where it
# has none (like the hasattr fallback below).
def unpack_default_getattr(archive_path, dest):
    tar = tarfile.open(archive_path)
    tar.extraction_filter = getattr(tarfile, "data_filter", (lambda member, path: member))
    # ruleid: python.tar-extraction
    tar.extractall(dest)


# The same getattr as the filter argument is safe: without filters, extractall() has no filter
# keyword and raises TypeError.
def safe_getattr_argument(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        # ok: python.tar-extraction
        tar.extractall(dest, filter=getattr(tarfile, "tar_filter", lambda member, path: member))


# A subset chosen by name (the docs' members= example) is still extracted unfiltered.
def py_files(members):
    for tarinfo in members:
        if os.path.splitext(tarinfo.name)[1] == ".py":
            yield tarinfo


def unpack_sources(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        # ruleid: python.tar-extraction
        tar.extractall(dest, members=py_files(tar))


# The docs' fallback for Pythons without filters: the else branch extracts unfiltered.
def unpack_fallback(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        if hasattr(tarfile, "data_filter"):
            # ok: python.tar-extraction
            tar.extractall(dest, filter="data")
        else:
            print("Extracting may be unsafe; consider updating Python")
            # ruleid: python.tar-extraction
            tar.extractall(dest)


# A loop that looks at the members but does not stop the extraction.
def unpack_logged(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            if member.name.startswith("/") or ".." in member.name:
                print("suspicious member", member.name)
        # ruleid: python.tar-extraction
        tar.extractall(dest)


def unpack_skipped(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            if member.name.startswith("/"):
                continue
        # ruleid: python.tar-extraction
        tar.extractall(dest)


def unpack_unrelated_check(archive_path, dest, dry_run):
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            if dry_run:
                return
        # ruleid: python.tar-extraction
        tar.extractall(dest)


def unpack_nested_exit(archive_path, dest, strict):
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            if os.path.isabs(member.name):
                if strict:
                    raise ValueError(member.name)
        # ruleid: python.tar-extraction
        tar.extractall(dest)


# A check on a character prefix: "/srv/data-evil/x" starts with "/srv/data".
def unpack_prefix_raise(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            target = os.path.realpath(os.path.join(root, member.name))
            if not target.startswith(root):
                raise ValueError("outside the destination")
        # ruleid: python.tar-extraction
        tar.extractall(root)


def unpack_prefix_raise_logged(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            target = os.path.realpath(os.path.join(root, member.name))
            if not target.startswith(root):
                print("outside the destination", target)
                raise ValueError("outside the destination")
        # ruleid: python.tar-extraction
        tar.extractall(root)


def unpack_prefix_return(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            target = os.path.realpath(os.path.join(root, member.name))
            if not target.startswith(root):
                return False
        # ruleid: python.tar-extraction
        tar.extractall(root)


def unpack_prefix_return_logged(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            target = os.path.realpath(os.path.join(root, member.name))
            if not target.startswith(root):
                print("outside the destination", target)
                return False
        # ruleid: python.tar-extraction
        tar.extractall(root)


def unpack_prefix_exit(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            target = os.path.realpath(os.path.join(root, member.name))
            if not target.startswith(root):
                sys.exit("outside the destination")
        # ruleid: python.tar-extraction
        tar.extractall(root)


def unpack_prefix_exit_logged(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            target = os.path.realpath(os.path.join(root, member.name))
            if not target.startswith(root):
                print("outside the destination", target)
                sys.exit("outside the destination")
        # ruleid: python.tar-extraction
        tar.extractall(root)


def unpack_prefix_skip(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar:
            target = os.path.realpath(os.path.join(root, member.name))
            if not target.startswith(root):
                continue
            # ruleid: python.tar-extraction
            tar.extract(member, root)


def unpack_prefix_skip_logged(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar:
            target = os.path.realpath(os.path.join(root, member.name))
            if not target.startswith(root):
                print("outside the destination", target)
                continue
            # ruleid: python.tar-extraction
            tar.extract(member, root)


def unpack_commonprefix_raise(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            target = os.path.realpath(os.path.join(root, member.name))
            if os.path.commonprefix([root, target]) != root:
                raise ValueError("outside the destination")
        # ruleid: python.tar-extraction
        tar.extractall(root)


def unpack_commonprefix_raise_logged(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            target = os.path.realpath(os.path.join(root, member.name))
            if os.path.commonprefix([root, target]) != root:
                print("outside the destination", target)
                raise ValueError("outside the destination")
        # ruleid: python.tar-extraction
        tar.extractall(root)


def unpack_commonprefix_return(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            target = os.path.realpath(os.path.join(root, member.name))
            if os.path.commonprefix([root, target]) != root:
                return False
        # ruleid: python.tar-extraction
        tar.extractall(root)


def unpack_commonprefix_return_logged(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            target = os.path.realpath(os.path.join(root, member.name))
            if os.path.commonprefix([root, target]) != root:
                print("outside the destination", target)
                return False
        # ruleid: python.tar-extraction
        tar.extractall(root)


def unpack_commonprefix_exit(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            target = os.path.realpath(os.path.join(root, member.name))
            if os.path.commonprefix([root, target]) != root:
                sys.exit("outside the destination")
        # ruleid: python.tar-extraction
        tar.extractall(root)


def unpack_commonprefix_exit_logged(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            target = os.path.realpath(os.path.join(root, member.name))
            if os.path.commonprefix([root, target]) != root:
                print("outside the destination", target)
                sys.exit("outside the destination")
        # ruleid: python.tar-extraction
        tar.extractall(root)


def unpack_commonprefix_skip(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar:
            target = os.path.realpath(os.path.join(root, member.name))
            if os.path.commonprefix([root, target]) != root:
                continue
            # ruleid: python.tar-extraction
            tar.extract(member, root)


def unpack_commonprefix_skip_logged(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar:
            target = os.path.realpath(os.path.join(root, member.name))
            if os.path.commonprefix([root, target]) != root:
                print("outside the destination", target)
                continue
            # ruleid: python.tar-extraction
            tar.extract(member, root)


# A path guard next to a selection of members by a name prefix.
SKIPPED_PREFIX = "docs/"


def safe_selected(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            if member.name.startswith(SKIPPED_PREFIX):
                continue
            target = os.path.realpath(os.path.join(root, member.name))
            if os.path.commonpath([root, target]) != root:
                raise ValueError("outside the destination")
        # ok: python.tar-extraction
        tar.extractall(root)


# A tar kept by __init__.
class Bundle:
    def __init__(self, archive_path):
        self.tar = tarfile.open(archive_path)

    def install(self, dest):
        # ruleid: python.tar-extraction
        self.tar.extractall(dest)

    def install_checked(self, dest):
        # ok: python.tar-extraction
        self.tar.extractall(dest, filter="data")


# shutil.unpack_archive passes filter to the tar unpacker.
def unpack_shutil(archive_path, dest):
    # ruleid: python.tar-extraction
    shutil.unpack_archive(archive_path, dest)


def unpack_shutil_format(archive_path, dest):
    # ruleid: python.tar-extraction
    shutil.unpack_archive(archive_path, extract_dir=dest, format="gztar")


def unpack_shutil_trusted(archive_path, dest):
    # ruleid: python.tar-extraction
    shutil.unpack_archive(archive_path, dest, filter="fully_trusted")


def unpack_shutil_none(archive_path, dest):
    # ruleid: python.tar-extraction
    shutil.unpack_archive(archive_path, dest, filter=None)
    # ruleid: python.tar-extraction
    shutil.unpack_archive(archive_path, dest, "gztar", filter=tarfile.fully_trusted_filter)
    # ruleid: python.tar-extraction
    shutil.unpack_archive(archive_path, dest, filter=lambda member, path: member)


def unpack_shutil_here(archive_path):
    # ruleid: python.tar-extraction
    shutil.unpack_archive(archive_path)


# Safe: the data or tar filter, by name or as a function, a constant naming one, and a filter of
# the application's own.
def safe_data(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        # ok: python.tar-extraction
        tar.extractall(dest, filter="data")


def safe_tar(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        # ok: python.tar-extraction
        tar.extractall(path=dest, filter="tar")


def safe_constant(archive_path, dest):
    tar = tarfile.open(archive_path)
    # ok: python.tar-extraction
    tar.extractall(dest, filter=DATA)


def safe_function(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        # ok: python.tar-extraction
        tar.extractall(dest, filter=tarfile.data_filter)


def safe_tar_function(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        # ok: python.tar-extraction
        tar.extractall(dest, filter=tarfile.tar_filter)


def safe_imported(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        # ok: python.tar-extraction
        tar.extractall(dest, filter=data_filter)
        # ok: python.tar-extraction
        tar.extract("README", dest, filter=tar_filter)


def regular_files_only(member, path):
    member = tarfile.data_filter(member, path)
    if not member.isfile():
        return None
    return member


def safe_custom(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        # ok: python.tar-extraction
        tar.extractall(dest, filter=regular_files_only)


def safe_lambda(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        # ok: python.tar-extraction
        tar.extractall(dest, filter=lambda member, path: tarfile.data_filter(member, path))


def safe_member(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            # ok: python.tar-extraction
            tar.extract(member, dest, filter="data")


# Safe: the instance's default filter set to data or tar before the call (the docs' forms).
def safe_default(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        tar.extraction_filter = tarfile.data_filter
        # ok: python.tar-extraction
        tar.extractall(dest)


# Safe: each member's path checked first, by an if on the member (or on a path computed from it
# in the loop) whose last statement leaves the function, or, for extract() in the loop, skips
# the member; the exit alone or after one statement. The checks compare whole path components
# (commonpath) or a prefix that ends in a separator.
def safe_checked(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            if os.path.commonpath([root, os.path.realpath(os.path.join(root, member.name))]) != root:
                raise ValueError("outside the destination: " + member.name)
        # ok: python.tar-extraction
        tar.extractall(root)


def safe_checked_logged(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar:
            if not os.path.realpath(os.path.join(root, member.name)).startswith(root + os.sep):
                print("outside the destination", member.name)
                raise ValueError(member.name)
        # ok: python.tar-extraction
        tar.extractall(root)


def safe_checked_return(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            if os.path.commonpath([root, os.path.realpath(os.path.join(root, member.name))]) != root:
                return False
        # ok: python.tar-extraction
        tar.extractall(root)


def safe_checked_return_logged(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            if not os.path.realpath(os.path.join(root, member.name)).startswith(root + os.sep):
                print("outside the destination", member.name)
                return None
        # ok: python.tar-extraction
        tar.extractall(root)


def safe_checked_exit(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            if os.path.commonpath([root, os.path.realpath(os.path.join(root, member.name))]) != root:
                sys.exit("outside the destination: " + member.name)
        # ok: python.tar-extraction
        tar.extractall(root)


# Safe: a members= generator of this file (defined before the call) that checks each member and
# leaves (raise, return, sys.exit) or skips it (continue) before it yields it: the same guard
# forms, on the member or on a path computed from it. A bad member is never extracted.
def members_checked(tar, root):
    for member in tar.getmembers():
        if os.path.commonpath([root, os.path.realpath(os.path.join(root, member.name))]) != root:
            raise ValueError("outside the destination: " + member.name)
        yield member


def members_skipped(tar, root):
    for member in tar:
        target = os.path.realpath(os.path.join(root, member.name))
        if not target.startswith(root + os.sep):
            print("skipping", member.name)
            continue
        yield member


def members_stopped(members, root):
    for info in members:
        if os.path.isabs(info.name) or ".." in info.name.split("/"):
            return
        yield info


def members_exited(tar, root):
    for member in tar:
        if os.path.commonpath([root, os.path.realpath(os.path.join(root, member.name))]) != root:
            sys.exit("outside the destination: " + member.name)
        yield member


def members_logged_skipped(tar, root):
    for member in tar:
        if os.path.isabs(member.name):
            print("absolute name", member.name)
            continue
        yield member


def members_target_checked(tar, root):
    for member in tar:
        target = os.path.realpath(os.path.join(root, member.name))
        if os.path.commonpath([root, target]) != root:
            return
        yield member


def safe_members_generator(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        # ok: python.tar-extraction
        tar.extractall(root, members=members_checked(tar, root))
    with tarfile.open(archive_path) as tar:
        # ok: python.tar-extraction
        tar.extractall(path=root, members=members_skipped(tar, root))
    with tarfile.open(archive_path) as tar:
        # ok: python.tar-extraction
        tar.extractall(root, members=members_stopped(tar.getmembers(), root))
    with tarfile.open(archive_path) as tar:
        # ok: python.tar-extraction
        tar.extractall(root, members=members_exited(tar, root))
    with tarfile.open(archive_path) as tar:
        # ok: python.tar-extraction
        tar.extractall(root, members=members_logged_skipped(tar, root))
    with tarfile.open(archive_path) as tar:
        # ok: python.tar-extraction
        tar.extractall(root, members=members_target_checked(tar, root))


# A guarded generator does not cover a call that does not use it, nor one whose check only logs,
# is on a character prefix that a sibling directory passes, or is os.path.commonprefix().
def members_logged(tar, root):
    for member in tar:
        if os.path.isabs(member.name):
            print("absolute name", member.name)
        yield member


def members_prefixed(tar, root):
    for member in tar:
        if not os.path.realpath(os.path.join(root, member.name)).startswith(root):
            raise ValueError(member.name)
        yield member


def members_common_prefix(tar, root):
    for member in tar:
        target = os.path.realpath(os.path.join(root, member.name))
        if os.path.commonprefix([root, target]) != root:
            continue
        yield member


def members_prefixed_logged(tar, root):
    for member in tar:
        if not os.path.realpath(os.path.join(root, member.name)).startswith(root):
            print("outside", member.name)
            return
        yield member


def members_prefixed_exit(tar, root):
    for member in tar:
        if not os.path.realpath(os.path.join(root, member.name)).startswith(root):
            sys.exit(1)
        yield member


def members_prefixed_skip(tar, root):
    for member in tar:
        if not os.path.realpath(os.path.join(root, member.name)).startswith(root):
            continue
        yield member


def members_common_prefix_logged(tar, root):
    for member in tar:
        if os.path.commonprefix([root, os.path.realpath(os.path.join(root, member.name))]) != root:
            print("outside", member.name)
            return
        yield member


def members_common_prefix_return(tar, root):
    for member in tar:
        if os.path.commonprefix([root, os.path.realpath(os.path.join(root, member.name))]) != root:
            return
        yield member


def members_common_prefix_exit(tar, root):
    for member in tar:
        if os.path.commonprefix([root, os.path.realpath(os.path.join(root, member.name))]) != root:
            sys.exit(1)
        yield member


def members_nested_check(tar, root, strict):
    for member in tar:
        if os.path.isabs(member.name):
            if strict:
                raise ValueError(member.name)
        yield member


def unsafe_members_generator(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        # ruleid: python.tar-extraction
        tar.extractall(root)
    with tarfile.open(archive_path) as tar:
        # ruleid: python.tar-extraction
        tar.extractall(root, members=members_logged(tar, root))
    with tarfile.open(archive_path) as tar:
        # ruleid: python.tar-extraction
        tar.extractall(root, members=members_prefixed(tar, root))
    with tarfile.open(archive_path) as tar:
        # ruleid: python.tar-extraction
        tar.extractall(root, members=members_common_prefix(tar, root))
    with tarfile.open(archive_path) as tar:
        # ruleid: python.tar-extraction
        tar.extractall(root, members=tar.getmembers())
    with tarfile.open(archive_path) as tar:
        # ruleid: python.tar-extraction
        tar.extractall(root, members=members_prefixed_logged(tar, root))
    with tarfile.open(archive_path) as tar:
        # ruleid: python.tar-extraction
        tar.extractall(root, members=members_prefixed_exit(tar, root))
    with tarfile.open(archive_path) as tar:
        # ruleid: python.tar-extraction
        tar.extractall(root, members=members_prefixed_skip(tar, root))
    with tarfile.open(archive_path) as tar:
        # ruleid: python.tar-extraction
        tar.extractall(root, members=members_common_prefix_logged(tar, root))
    with tarfile.open(archive_path) as tar:
        # ruleid: python.tar-extraction
        tar.extractall(root, members=members_common_prefix_return(tar, root))
    with tarfile.open(archive_path) as tar:
        # ruleid: python.tar-extraction
        tar.extractall(root, members=members_common_prefix_exit(tar, root))
    with tarfile.open(archive_path) as tar:
        # ruleid: python.tar-extraction
        tar.extractall(root, members=members_nested_check(tar, root, False))


def safe_checked_exit_logged(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            if not os.path.realpath(os.path.join(root, member.name)).startswith(root + os.sep):
                print("outside the destination", member.name)
                sys.exit(1)
        # ok: python.tar-extraction
        tar.extractall(root)


def safe_skip(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar:
            if os.path.commonpath([root, os.path.realpath(os.path.join(root, member.name))]) != root:
                continue
            # ok: python.tar-extraction
            tar.extract(member, root)


def safe_skip_logged(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            if not os.path.realpath(os.path.join(root, member.name)).startswith(root + os.sep):
                print("outside the destination", member.name)
                continue
            # ok: python.tar-extraction
            tar.extract(member, root)


def safe_within(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            target = os.path.realpath(os.path.join(root, member.name))
            if os.path.commonpath([root, target]) != root:
                raise ValueError("outside the destination")
        # ok: python.tar-extraction
        tar.extractall(root)


def safe_within_logged(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            target = os.path.realpath(os.path.join(root, member.name))
            if not target.startswith(root + os.sep):
                print("outside the destination", member.name)
                raise ValueError(target)
        # ok: python.tar-extraction
        tar.extractall(root)


def safe_within_return(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar:
            target = os.path.realpath(os.path.join(root, member.name))
            if os.path.commonpath([root, target]) != root:
                return False
        # ok: python.tar-extraction
        tar.extractall(root)


def safe_within_return_logged(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar:
            target = os.path.realpath(os.path.join(root, member.name))
            if not target.startswith(root + "/"):
                print("outside the destination", member.name)
                return False
        # ok: python.tar-extraction
        tar.extractall(root)


def safe_within_exit(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            target = os.path.realpath(os.path.join(root, member.name))
            if os.path.commonpath([root, target]) != root:
                sys.exit("outside the destination")
        # ok: python.tar-extraction
        tar.extractall(root)


def safe_within_exit_logged(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            target = os.path.realpath(os.path.join(root, member.name))
            if not target.startswith(os.path.join(root, "")):
                print("outside the destination", member.name)
                sys.exit(2)
        # ok: python.tar-extraction
        tar.extractall(root)


def safe_within_skip(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar:
            target = os.path.realpath(os.path.join(root, member.name))
            if os.path.commonpath([root, target]) != root:
                continue
            # ok: python.tar-extraction
            tar.extract(member, root)


def safe_within_skip_logged(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar:
            target = os.path.realpath(os.path.join(root, member.name))
            if not target.startswith(root + os.path.sep):
                print("outside the destination", member.name)
                continue
            # ok: python.tar-extraction
            tar.extract(member, root)


# Safe: shutil with a filter, and zip archives (zipfile sanitises member names; zip takes no
# filter).
def safe_shutil(archive_path, dest):
    # ok: python.tar-extraction
    shutil.unpack_archive(archive_path, dest, filter="data")
    # ok: python.tar-extraction
    shutil.unpack_archive(archive_path, dest, format="gztar", filter=tarfile.data_filter)
    # ok: python.tar-extraction
    shutil.unpack_archive(archive_path, dest, format="zip")
    # ok: python.tar-extraction
    shutil.unpack_archive(archive_path, dest, "zip")
    # ok: python.tar-extraction
    shutil.unpack_archive("assets/fonts.zip", dest)


# Look-alikes: other archive libraries' extractall/extract, and tarfile calls that write nothing.
def zip_files(archive_path, dest):
    with zipfile.ZipFile(archive_path) as zf:
        # ok: python.tar-extraction
        zf.extractall(dest)
        # ok: python.tar-extraction
        zf.extract("README", dest)
    # ok: python.tar-extraction
    zipfile.ZipFile(archive_path).extractall(dest)


def seven_zip(archive_path, dest):
    with py7zr.SevenZipFile(archive_path, mode="r") as archive:
        # ok: python.tar-extraction
        archive.extractall(path=dest)


def read_member(archive_path):
    with tarfile.open(archive_path) as tar:
        # ok: python.tar-extraction
        return tar.extractfile("config/settings.ini").read()


def pack(dest, files):
    with tarfile.open(dest, "w:gz") as tar:
        for name in files:
            # ok: python.tar-extraction
            tar.add(name, filter=None)


# Known limits.
# A tar from a parameter without a type or from a factory function is not followed.
def extract_to(tar, dest):
    # todoruleid: python.tar-extraction
    tar.extractall(dest)


# Options passed as a dict are not read.
def unpack_options(archive_path, dest):
    opts = {"filter": "fully_trusted"}
    with tarfile.open(archive_path) as tar:
        # todoruleid: python.tar-extraction
        tar.extractall(dest, **opts)
    # todoruleid: python.tar-extraction
    shutil.unpack_archive(archive_path, dest, **opts)


# Any check of the member that leaves counts, even one that does not look at its path ("../x" is a
# regular file) or links.
def unpack_type_check(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            if member.isdev():
                sys.exit("device files are not allowed")
        # todoruleid: python.tar-extraction
        tar.extractall(dest)


def unpack_type_skip(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        for member in tar:
            if not member.isfile():
                continue
            # todoruleid: python.tar-extraction
            tar.extract(member, dest)


# Literal and f-string prefixes without a separator count as guards.
def unpack_literal_prefix(archive_path):
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            target = os.path.realpath(os.path.join("/srv/data", member.name))
            if not target.startswith("/srv/data"):
                raise ValueError("outside the destination")
        # todoruleid: python.tar-extraction
        tar.extractall("/srv/data")


def unpack_fstring_prefix(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            target = os.path.realpath(os.path.join(root, member.name))
            if not target.startswith(f"{root}"):
                raise ValueError("outside the destination")
        # todoruleid: python.tar-extraction
        tar.extractall(root)


# A selection by a name prefix that skips members, before extract() in the loop, is taken for a
# character-prefix guard.
def unpack_selected_members(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in tar:
            if member.name.startswith(SKIPPED_PREFIX):
                continue
            if os.path.commonpath([root, os.path.realpath(os.path.join(root, member.name))]) != root:
                continue
            # todook: python.tar-extraction
            tar.extract(member, root)


# A named filter that returns each member unchanged (fully_trusted under another name).
def keep_everything(member, path):
    return member


def unpack_named_identity(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        # todoruleid: python.tar-extraction
        tar.extractall(dest, filter=keep_everything)


# A prefix that ends in a separator but is held in a variable is taken for a character prefix.
def unpack_prefix_variable(archive_path, dest):
    root = os.path.realpath(dest)
    prefix = root + os.sep
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            target = os.path.realpath(os.path.join(root, member.name))
            if not target.startswith(prefix):
                raise ValueError("outside the destination")
        # todook: python.tar-extraction
        tar.extractall(root)


# Safe: a helper of this file (defined before the call) that loops over the members with the same
# check and raises or calls sys.exit on a bad one, called with the archive before the extraction
# in the same block: a bad member stops the program before anything is extracted.
def refuse_outside(tar, root):
    for member in tar.getmembers():
        if os.path.commonpath([root, os.path.realpath(os.path.join(root, member.name))]) != root:
            raise ValueError("outside the destination: " + member.name)


def refuse_absolute(members):
    for member in members:
        target = member.name
        if os.path.isabs(target) or ".." in target.split("/"):
            print("refusing", target)
            sys.exit(1)


def refuse_absolute_logged(tar):
    for member in tar:
        if os.path.isabs(member.name):
            print("absolute name", member.name)
            raise ValueError(member.name)


def refuse_target(tar, root):
    for member in tar:
        target = os.path.realpath(os.path.join(root, member.name))
        if os.path.commonpath([root, target]) != root:
            raise ValueError(member.name)


def safe_helper_checked(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        refuse_outside(tar, root)
        # ok: python.tar-extraction
        tar.extractall(root)
    with tarfile.open(archive_path) as tar:
        refuse_absolute_logged(tar)
        # ok: python.tar-extraction
        tar.extractall(root)
    with tarfile.open(archive_path) as tar:
        refuse_target(tar, root)
        # ok: python.tar-extraction
        tar.extractall(root)
    with tarfile.open(archive_path) as tar:
        refuse_absolute(tar.getmembers())
        for member in tar.getmembers():
            # ok: python.tar-extraction
            tar.extract(member, root)


# A helper that only returns (the caller extracts anyway), logs, checks after the extraction or
# another archive, or checks a character prefix or os.path.commonprefix() is no guard.
def report_outside(tar, root):
    for member in tar.getmembers():
        if os.path.commonpath([root, os.path.realpath(os.path.join(root, member.name))]) != root:
            return False
    return True


def log_outside(tar, root):
    for member in tar:
        if os.path.isabs(member.name):
            print("absolute name", member.name)


def refuse_prefixed(tar, root):
    for member in tar:
        if not os.path.realpath(os.path.join(root, member.name)).startswith(root):
            raise ValueError(member.name)


def refuse_common_prefix(tar, root):
    for member in tar:
        if os.path.commonprefix([root, os.path.realpath(os.path.join(root, member.name))]) != root:
            raise ValueError(member.name)


def refuse_prefixed_logged(tar, root):
    for member in tar:
        if not os.path.realpath(os.path.join(root, member.name)).startswith(root):
            print("outside", member.name)
            raise ValueError(member.name)


def refuse_common_prefix_logged(tar, root):
    for member in tar:
        if os.path.commonprefix([root, os.path.realpath(os.path.join(root, member.name))]) != root:
            print("outside", member.name)
            sys.exit(1)


def unsafe_helper_checked(archive_path, other_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        report_outside(tar, root)
        # ruleid: python.tar-extraction
        tar.extractall(root)
    with tarfile.open(archive_path) as tar:
        log_outside(tar, root)
        # ruleid: python.tar-extraction
        tar.extractall(root)
    with tarfile.open(archive_path) as tar:
        # ruleid: python.tar-extraction
        tar.extractall(root)
        refuse_outside(tar, root)
    with tarfile.open(archive_path) as tar, tarfile.open(other_path) as other:
        refuse_outside(other, root)
        # ruleid: python.tar-extraction
        tar.extractall(root)
    with tarfile.open(archive_path) as tar:
        refuse_prefixed(tar, root)
        # ruleid: python.tar-extraction
        tar.extractall(root)
    with tarfile.open(archive_path) as tar:
        refuse_common_prefix(tar, root)
        # ruleid: python.tar-extraction
        tar.extractall(root)
    with tarfile.open(archive_path) as tar:
        refuse_prefixed_logged(tar, root)
        # ruleid: python.tar-extraction
        tar.extractall(root)
    with tarfile.open(archive_path) as tar:
        refuse_common_prefix_logged(tar, root)
        # ruleid: python.tar-extraction
        tar.extractall(root)
    with tarfile.open(archive_path) as tar:
        refuse_prefixed(tar.getmembers(), root)
        # ruleid: python.tar-extraction
        tar.extractall(root)
    with tarfile.open(archive_path) as tar:
        refuse_common_prefix(tar.getmembers(), root)
        # ruleid: python.tar-extraction
        tar.extractall(root)


# A helper is not checked to loop over the archive it is given: one that checks other names
# counts as a guard.
def refuse_reserved(tar, names):
    for name in names:
        if name in ("con", "nul"):
            raise ValueError(name)


def unpack_unrelated_helper(archive_path, dest, names):
    with tarfile.open(archive_path) as tar:
        refuse_reserved(tar, names)
        # todoruleid: python.tar-extraction
        tar.extractall(dest)


# A checking generator called on its own is taken for a checking helper, although its body never
# runs without iteration.
def unpack_generator_called(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        members_checked(tar, root)
        # todoruleid: python.tar-extraction
        tar.extractall(root)


# A default filter set on the TarFile class for the whole program (the docs' global default; the
# other cases of this file assume none is set) is not seen.
def configure_tarfile():
    tarfile.TarFile.extraction_filter = staticmethod(tarfile.data_filter)


def unpack_after_configure(archive_path, dest):
    configure_tarfile()
    with tarfile.open(archive_path) as tar:
        # todook: python.tar-extraction
        tar.extractall(dest)


# A checking helper defined after its caller, a checking method called on self, and a helper whose
# result decides (`if not inside(tar, root): raise ...`) are not read.
def unpack_helper_later(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        check_members_later(tar, dest)
        # todook: python.tar-extraction
        tar.extractall(dest)


def check_members_later(tar, dest):
    for member in tar.getmembers():
        if os.path.isabs(member.name):
            raise ValueError(member.name)


class Unpacker:
    def check(self, tar):
        for member in tar.getmembers():
            if os.path.isabs(member.name):
                raise ValueError(member.name)

    def unpack(self, archive_path, dest):
        with tarfile.open(archive_path) as tar:
            self.check(tar)
            # todook: python.tar-extraction
            tar.extractall(dest)


def unpack_helper_result(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        if not report_outside(tar, root):
            raise ValueError("outside the destination")
        # todook: python.tar-extraction
        tar.extractall(root)


# A check of the member inside another condition counts although it leaves only on some paths.
def unpack_conditional_check(archive_path, dest, strict):
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            if strict:
                if os.path.isabs(member.name):
                    raise ValueError(member.name)
        # todoruleid: python.tar-extraction
        tar.extractall(dest)


# A members= generator that yields only inside a check (`if inside: yield member`) has the form of
# the docs' name selection (py_files above), so it is not read as a guard.
def members_inside(tar, root):
    for member in tar:
        target = os.path.realpath(os.path.join(root, member.name))
        if os.path.commonpath([root, target]) == root:
            yield member


def unpack_checked_members(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        # todook: python.tar-extraction
        tar.extractall(root, members=members_inside(tar, root))


# A guarded members= generator defined after the call, or used by a loop that calls extract(), is
# not read.
def unpack_checked_later(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        # todook: python.tar-extraction
        tar.extractall(root, members=members_checked_later(tar, root))


def members_checked_later(tar, root):
    for member in tar:
        if os.path.isabs(member.name):
            raise ValueError(member.name)
        yield member


def unpack_checked_loop(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for member in members_checked(tar, root):
            # todook: python.tar-extraction
            tar.extract(member, root)


# Guards the rule does not read: more than one statement before the exit, and an exit by break.
def unpack_long_guard(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            if os.path.isabs(member.name):
                kind = "absolute"
                print("refusing", kind, member.name)
                raise ValueError(member.name)
        # todook: python.tar-extraction
        tar.extractall(dest)


def unpack_break_guard(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        for member in tar:
            if os.path.isabs(member.name):
                break
            # todook: python.tar-extraction
            tar.extract(member, dest)


# shutil cannot tell a zip from a tar by a variable path.
def unpack_zip_variable(zip_path, dest):
    # todook: python.tar-extraction
    shutil.unpack_archive(zip_path, dest)
