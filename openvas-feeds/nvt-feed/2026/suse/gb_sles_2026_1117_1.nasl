# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.1117.1");
  script_cve_id("CVE-2025-11468", "CVE-2025-12084", "CVE-2025-13836", "CVE-2025-13837", "CVE-2025-15282", "CVE-2025-6075", "CVE-2026-0672", "CVE-2026-0865", "CVE-2026-1299", "CVE-2026-2297");
  script_tag(name:"creation_date", value:"2026-03-30 04:58:33 +0000 (Mon, 30 Mar 2026)");
  script_version("2026-03-30T06:15:36+0000");
  script_tag(name:"last_modification", value:"2026-03-30 06:15:36 +0000 (Mon, 30 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-10 19:58:12 +0000 (Tue, 10 Feb 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:1117-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4|SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:1117-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20261117-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252974");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254997");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257029");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257031");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257046");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257181");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259240");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/025015.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python311' package(s) announced via the SUSE-SU-2026:1117-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python311 fixes the following issues:

Update to python 3.11.15:

- CVE-2025-6075: quadratic complexity in os.path.expandvars() (bsc#1252974).
- CVE-2025-11468: header injection with carefully crafted inputs (bsc#1257029).
- CVE-2025-12084: quadratic complexity in xml.minidom node ID cache clearing (bsc#1254997).
- CVE-2025-13836: potential memory denial of service in the http.client module (bsc#1254400).
- CVE-2025-13837: potential memory denial of service in the plistlib module (bsc#1254401).
- CVE-2025-15282: user-controlled data URLs parsed may allow injecting headers (bsc#1257046).
- CVE-2026-0672: control characters in http.cookies.Morsel fields and values (bsc#1257031).
- CVE-2026-0865: C0 control characters within wsgiref.headers.Headers fields, values, and parameters (bsc#1257042).
- CVE-2026-1299: header injection when an email is serialized due to improper newline quoting (bsc#1257181).
- CVE-2026-2297: validation bypass via incorrectly handled hook in FileLoader (bsc#1259240).

Changelog:

 - gh-144125: BytesGenerator will now refuse to serialize
 (write) headers that are unsafely folded or delimited, see
 verify_generated_headers. (Contributed by Bas Bloemsaat and
 Petr Viktorin in gh-121650) (bsc#1257181, CVE-2026-1299).
 - gh-143935: Fixed a bug in the folding of comments when
 flattening an email message using a modern email policy.
 Comments consisting of a very long sequence of non-foldable
 characters could trigger a forced line wrap that omitted
 the required leading space on the continuation line,
 causing the remainder of the comment to be interpreted as
 a new header field. This enabled header injection with
 carefully crafted inputs (bsc#1257029 CVE-2025-11468).
 - gh-143925: Reject control characters in data: URL media
 types (bsc#1257046, CVE-2025-15282).
 - gh-143919: Reject control characters in http.cookies.Morsel
 fields and values (bsc#1257031, CVE-2026-0672).
 - gh-143916: Reject C0 control characters within
 wsgiref.headers.Headers fields, values, and parameters
 (bsc#1257042, CVE-2026-0865).
 - gh-142145: Remove quadratic behavior in xml.minidom node ID
 cache clearing. In order to do this without breaking
 existing users, we also add the ownerDocument attribute to
 xml.dom.minidom elements and attributes created by directly
 instantiating the Element or Attr class. Note that this way
 of creating nodes is not supported, creator functions like
 xml.dom.Document.documentElement() should be used instead
 (bsc#1254997, CVE-2025-12084).
 - gh-137836: Add support of the 'plaintext' element, RAWTEXT
 elements 'xmp', 'iframe', 'noembed' and 'noframes', and
 optionally RAWTEXT element 'noscript' in
 html.parser.HTMLParser.
 - gh-136063: email.message: ensure linear complexity for
 legacy HTTP parameters parsing. Patch by Benedikt Tran.
 - gh-136065: Fix quadratic complexity in
 os.path.expandvars() (bsc#1252974, CVE-2025-6075).
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'python311' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libpython3_11-1_0", rpm:"libpython3_11-1_0~3.11.15~150400.9.80.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311", rpm:"python311~3.11.15~150400.9.80.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-base", rpm:"python311-base~3.11.15~150400.9.80.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-curses", rpm:"python311-curses~3.11.15~150400.9.80.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-dbm", rpm:"python311-dbm~3.11.15~150400.9.80.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-devel", rpm:"python311-devel~3.11.15~150400.9.80.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-doc", rpm:"python311-doc~3.11.15~150400.9.80.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-doc-devhelp", rpm:"python311-doc-devhelp~3.11.15~150400.9.80.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-idle", rpm:"python311-idle~3.11.15~150400.9.80.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-tk", rpm:"python311-tk~3.11.15~150400.9.80.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-tools", rpm:"python311-tools~3.11.15~150400.9.80.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libpython3_11-1_0", rpm:"libpython3_11-1_0~3.11.15~150400.9.80.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311", rpm:"python311~3.11.15~150400.9.80.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-base", rpm:"python311-base~3.11.15~150400.9.80.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-curses", rpm:"python311-curses~3.11.15~150400.9.80.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-dbm", rpm:"python311-dbm~3.11.15~150400.9.80.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-devel", rpm:"python311-devel~3.11.15~150400.9.80.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-doc", rpm:"python311-doc~3.11.15~150400.9.80.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-doc-devhelp", rpm:"python311-doc-devhelp~3.11.15~150400.9.80.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-idle", rpm:"python311-idle~3.11.15~150400.9.80.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-tk", rpm:"python311-tk~3.11.15~150400.9.80.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-tools", rpm:"python311-tools~3.11.15~150400.9.80.1", rls:"SLES15.0SP5"))) {
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
