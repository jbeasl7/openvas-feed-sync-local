# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.814971100101101998");
  script_tag(name:"creation_date", value:"2026-02-27 04:36:52 +0000 (Fri, 27 Feb 2026)");
  script_version("2026-02-27T05:55:46+0000");
  script_tag(name:"last_modification", value:"2026-02-27 05:55:46 +0000 (Fri, 27 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-814a1deec8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-814a1deec8");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-814a1deec8");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2442507");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libmaxminddb' package(s) announced via the FEDORA-2026-814a1deec8 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"# libmaxminddb 1.13.1
- Re-release for Ubuntu PPA, no code changes.

# libmaxminddb 1.13.0
- `MMDB_get_entry_data_list()` now validates that the claimed array/map size is
 plausible given the remaining bytes in the data section. A crafted database
 could previously claim millions of array elements while only having a few
 bytes of data, causing disproportionate memory allocation (memory
 amplification DoS).
- Fixed integer overflow in `MMDB_read_node()` and `find_ipv4_start_node()`
 pointer arithmetic. The `node_number * record_length` multiplication was
 performed in `uint32_t`, which could overflow for very large databases. Now
 cast to `uint64_t` before multiplying, matching the pattern already used in
 `find_address_in_search_tree()`.
- Fixed printf format specifier mismatches in `mmdblookup`'s metadata dump. `%i`
 was used for unsigned types and `%llu` for `uint64_t`, which is technically
 undefined behavior. Now uses the portable `PRIu32`, `PRIu16`, and `PRIu64`
 macros from `<inttypes.h>`.
- Fixed an integer overflow in the search tree bounds check in
 `find_address_in_search_tree()`. The addition of `node_count` and
 `data_section_size` was performed in `uint32_t` arithmetic, which could wrap
 on very large databases, causing valid lookups to be incorrectly rejected as
 corrupt.
- Fixed a NULL pointer dereference in `mmdblookup` when displaying metadata for
 a database with an out-of-range `build_epoch`. The `gmtime()` return value is
 now checked before passing to `strftime()`.
- `MMDB_close()` now NULLs the `file_content`, `data_section`, and
 `metadata_section` pointers and zeroes `file_size`, `data_section_size`, and
 `metadata_section_size` after unmapping. Previously, calling `MMDB_close()`
 twice on the same struct (or calling it after a failed `MMDB_open()` that
 succeeded at mapping) would double-munmap the file content, which is undefined
 behavior.
- Fixed a stack buffer overflow in `print_indentation()` when
 `MMDB_dump_entry_data_list()` was called with a negative `indent` value. The
 negative integer was cast to `size_t`, producing a massive value passed to
 `memset()`. Negative indent values are now clamped to 0.
- `MMDB_lookup_string()` now sets `*mmdb_error` to `MMDB_SUCCESS` when
 `getaddrinfo` fails (non-zero `*gai_error`). Previously, `*mmdb_error` was
 left uninitialized in this case, which could cause callers to read an
 indeterminate value.
- Added a recursion depth limit to `skip_map_or_array()`, matching the existing
 `MAXIMUM_DATA_STRUCTURE_DEPTH` (512) limit already used by
 `get_entry_data_list()`. A crafted MMDB file with deeply nested maps or arrays
 could previously cause a stack overflow via unbounded recursion in the
 `MMDB_aget_value` / `MMDB_get_value` code path.
- Fixed an off-by-one error in `MMDB_read_node()` that allowed reading one node
 past the end of the search tree when called with `node_number == node_count`.
 This ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'libmaxminddb' package(s) on Fedora 43.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"libmaxminddb", rpm:"libmaxminddb~1.13.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmaxminddb-debuginfo", rpm:"libmaxminddb-debuginfo~1.13.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmaxminddb-debugsource", rpm:"libmaxminddb-debugsource~1.13.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmaxminddb-devel", rpm:"libmaxminddb-devel~1.13.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
