# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20032.1");
  script_cve_id("CVE-2025-13601", "CVE-2025-14087", "CVE-2025-14512", "CVE-2025-7039");
  script_tag(name:"creation_date", value:"2026-01-16 04:26:57 +0000 (Fri, 16 Jan 2026)");
  script_version("2026-01-28T05:49:43+0000");
  script_tag(name:"last_modification", value:"2026-01-28 05:49:43 +0000 (Wed, 28 Jan 2026)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-11-26 15:15:51 +0000 (Wed, 26 Nov 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20032-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20032-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620032-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249055");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254297");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254662");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254878");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023772.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glib2' package(s) announced via the SUSE-SU-2026:20032-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for glib2 fixes the following issues:

Update to version 2.84.4.

Security issues fixed:

- CVE-2025-14512: integer overflow in the GIO `escape_byte_string()` function when processing malicious files or remote
 filesystem attribute values can lead to denial-of-service (bsc#1254878).
- CVE-2025-14087: buffer underflow in the GVariant parser `bytestring_parse()` and `string_parse()` functions when
 processing attacker-influenced data may lead to crash or code execution (bsc#1254662).
- CVE-2025-13601: heap-based buffer overflow in the `g_escape_uri_string()` function when processing strings with a
 large number of unacceptable characters may lead to crash or code execution (bsc#1254297).
- CVE-2025-7039: integer overflow when creating temporary files may lead to an out-of-bounds memory access that can be
 used for path traversal or exposure of sensitive content in a temporary file (bsc#1249055).

Other issues fixed and changes:

- Fix GFile leak in `g_local_file_set_display_name` during error handling.
- Fix incorrect output parameter handling in closure helper of `g_settings_bind_with_mapping_closures`.
- `gfileutils`: fix computation of temporary file name.
- Fix GFile leak in `g_local_file_set_display_name()`.
- `gthreadpool`: catch `pool_spawner` creation failure.
- `gio/filenamecompleter`: fix leaks.
- `gfilenamecompleter`: fix `g_object_unref()` of undefined value.");

  script_tag(name:"affected", value:"'glib2' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"gio-branding-SLE", rpm:"gio-branding-SLE~16~160000.2.2", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2-devel", rpm:"glib2-devel~2.84.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2-devel-static", rpm:"glib2-devel-static~2.84.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2-doc", rpm:"glib2-doc~2.84.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2-lang", rpm:"glib2-lang~2.84.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2-tools", rpm:"glib2-tools~2.84.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgio-2_0-0", rpm:"libgio-2_0-0~2.84.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgirepository-2_0-0", rpm:"libgirepository-2_0-0~2.84.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglib-2_0-0", rpm:"libglib-2_0-0~2.84.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmodule-2_0-0", rpm:"libgmodule-2_0-0~2.84.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgobject-2_0-0", rpm:"libgobject-2_0-0~2.84.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgthread-2_0-0", rpm:"libgthread-2_0-0~2.84.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GIRepository-3_0", rpm:"typelib-1_0-GIRepository-3_0~2.84.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GLib-2_0", rpm:"typelib-1_0-GLib-2_0~2.84.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GLibUnix-2_0", rpm:"typelib-1_0-GLibUnix-2_0~2.84.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GModule-2_0", rpm:"typelib-1_0-GModule-2_0~2.84.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GObject-2_0", rpm:"typelib-1_0-GObject-2_0~2.84.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Gio-2_0", rpm:"typelib-1_0-Gio-2_0~2.84.4~160000.1.1", rls:"SLES16.0.0"))) {
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
