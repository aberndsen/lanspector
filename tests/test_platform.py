"""Unit tests for OS-abstracted permissions, NTFS bitmasks, and path/network helpers."""

from __future__ import annotations

import pathlib

import pandas as pd
from assertpy import assert_that

from lanspector.pii import count_pii_name_matches, extract_file_text, scan_file_for_pii
from lanspector.platform import (
    bitmask_to_code,
    clean_long_path,
    extract_domain_host_share_subdir,
    get_effective_permissions,
    get_fileshare_permissions,
    get_group_membership,
    get_path_owner,
    is_hostname,
    is_ip_address,
    ntfs_to_bitmask,
    reduce_permission_hierarchy,
    strip_long_path_prefix,
    subdir_fqdn_to_hostname,
)
from lanspector.shares import (
    list_all_shares_in_domain,
    list_servers_in_domain,
    list_shares,
    port_scan,
)


def test_ntfs_bitmask_roundtrip() -> None:
    """Verify bitmask encoding, aggregation, hierarchy reduction, and decoding."""
    assert_that(ntfs_to_bitmask("Read(RX)")).is_equal_to(1)
    assert_that(ntfs_to_bitmask("Add&Read")).is_equal_to(2)
    assert_that(ntfs_to_bitmask("Change")).is_equal_to(4)
    assert_that(ntfs_to_bitmask("Special")).is_equal_to(8)
    assert_that(ntfs_to_bitmask("Full Control(All)")).is_equal_to(32)
    assert_that(ntfs_to_bitmask("UnknownCustomMask")).is_equal_to(16)
    assert_that(ntfs_to_bitmask(None)).is_equal_to(0)

    assert_that(bitmask_to_code(0)).is_none()
    assert_that(bitmask_to_code(1)).is_equal_to("R")
    assert_that(bitmask_to_code(2)).is_equal_to("AR")
    assert_that(bitmask_to_code(5)).is_equal_to("RM")
    assert_that(bitmask_to_code(32)).is_equal_to("F")
    assert_that(bitmask_to_code(16)).is_equal_to("S")

    reduced = reduce_permission_hierarchy(pd.Series([0, 1, 5, 37]))
    assert_that(reduced.tolist()).is_equal_to([0, 1, 4, 32])


def test_posix_owner_and_permissions(tmp_path: pathlib.Path) -> None:
    """Verify POSIX fallback extracts owner and normalized permissions."""
    sample = tmp_path / "perm_check.txt"
    sample.write_text("hello", encoding="utf-8")
    sample.chmod(0o755)

    owner = get_path_owner(str(sample))
    assert_that(owner).is_not_empty()
    assert_that(owner).is_not_equal_to("AccessDenied")

    perms = get_effective_permissions(str(sample))
    assert_that(perms).is_not_empty()
    names = [p.name for p in perms]
    assert_that(names).contains("Everyone")


def test_path_and_network_helpers() -> None:
    """Verify IP, hostname, UNC parsing, and long-path normalization helpers."""
    assert_that(is_ip_address("192.168.1.10")).is_true()
    assert_that(is_ip_address("999.1.1.1")).is_false()
    assert_that(is_hostname("filesrv01")).is_true()
    assert_that(is_hostname("filesrv01.corp.example")).is_false()

    dom, host, share, subdir = extract_domain_host_share_subdir(
        r"\\filesrv01.corp.example\finance\q1\reports"
    )
    assert_that(dom).is_equal_to("corp.example")
    assert_that(host).is_equal_to("filesrv01")
    assert_that(share).is_equal_to("finance")
    assert_that(subdir).is_equal_to(r"q1\reports")

    was_fqdn, shortened = subdir_fqdn_to_hostname(r"\\filesrv01.corp.example\finance\q1")
    assert_that(was_fqdn).is_true()
    assert_that(shortened).is_equal_to(r"\\filesrv01\finance\q1")

    long_unc = "\\\\server\\share\\" + ("a" * 260)
    prefixed = clean_long_path(long_unc)
    assert_that(prefixed).starts_with("\\\\?\\UNC\\")
    assert_that(strip_long_path_prefix(prefixed)).is_equal_to(long_unc)

    long_drive = "C:\\" + ("b" * 260)
    assert_that(clean_long_path(long_drive)).starts_with("\\\\?\\")


def test_pii_scanning_excel_and_text(tmp_path: pathlib.Path) -> None:
    """Verify openpyxl and text PII scanning detects configured keywords."""
    fixture_xlsx = pathlib.Path(__file__).resolve().parent / "data" / "pii_test_document.xlsx"
    text = extract_file_text(fixture_xlsx)
    assert_that(text.lower()).contains("address")
    findings = scan_file_for_pii(fixture_xlsx, use_ner=False)
    assert_that(len(findings)).is_greater_than_or_equal_to(3)

    txt = tmp_path / "sample.csv"
    txt.write_text("ssn,phone\n123-45-6789,555-0199\n", encoding="utf-8")
    txt_findings = scan_file_for_pii(txt)
    assert_that(len(txt_findings)).is_greater_than_or_equal_to(2)
    assert_that(count_pii_name_matches("/data/payroll", "employee_ssn.csv")).is_greater_than(0)


def test_non_windows_share_helpers_graceful() -> None:
    """Verify Windows-only SMB/AD helpers degrade gracefully on non-Windows platforms."""
    assert_that(get_fileshare_permissions("/tmp")).is_equal_to([])
    assert_that(get_group_membership("CORP", "Admins").empty).is_true()
    assert_that(list_servers_in_domain("CORP")).is_equal_to([])
    assert_that(list_shares(servers=["localhost"])).is_equal_to([])
    assert_that(list_all_shares_in_domain("CORP")).is_equal_to([])

    scan = port_scan("127.0.0.1", port=1, timeout=0.1)
    assert_that(scan).contains_key("server", "fqdn", "connection")
