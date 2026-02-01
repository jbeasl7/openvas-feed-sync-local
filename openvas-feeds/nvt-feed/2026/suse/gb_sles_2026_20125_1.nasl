# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20125.1");
  script_cve_id("CVE-2025-12084", "CVE-2025-13836", "CVE-2025-13837", "CVE-2025-6069", "CVE-2025-6075", "CVE-2025-8194", "CVE-2025-8291");
  script_tag(name:"creation_date", value:"2026-01-30 04:34:32 +0000 (Fri, 30 Jan 2026)");
  script_version("2026-01-30T05:55:24+0000");
  script_tag(name:"last_modification", value:"2026-01-30 05:55:24 +0000 (Fri, 30 Jan 2026)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-30 15:08:14 +0000 (Tue, 30 Dec 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20125-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20125-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620125-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244680");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247249");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251305");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252974");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254997");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2026-January/043743.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python313' package(s) announced via the SUSE-SU-2026:20125-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python313 fixes the following issues:

- Update to 3.13.11:

- Security
 - CVE-2025-12084: cpython: Fixed quadratic algorithm in
 xml.dom.minidom leading to denial of service (bsc#1254997)
 - CVE-2025-13836: Fixed default Content-Lenght read amount
 from HTTP response (bsc#1254400)
 - CVE-2025-13837: Fixed plistlib module denial of service (bsc#1254401)
 - CVE-2025-8291: Fixed validity of the ZIP64 End of Central Directory
 (EOCD) not checked by the 'zipfile' module (bsc#1251305)
 - gh-137836: Add support of the 'plaintext' element, RAWTEXT
 elements 'xmp', 'iframe', 'noembed' and 'noframes', and
 optionally RAWTEXT element 'noscript' in
 html.parser.HTMLParser.
 - gh-136063: email.message: ensure linear complexity for
 legacy HTTP parameters parsing. Patch by Benedikt Tran.
 - CVE-2025-6075: Fixed performance issues caused by user-controller
 os.path.expandvars() (bsc#1252974)
- Library
 - gh-140797: Revert changes to the undocumented re.Scanner
 class. Capturing groups are still allowed for backward
 compatibility, although using them can lead to incorrect
 result. They will be forbidden in future Python versions.
 - gh-142206: The resource tracker in the multiprocessing
 module now uses the original communication protocol, as in
 Python 3.14.0 and below, by default. This avoids issues
 with upgrading Python while it is running. (Note that such
 'in-place' upgrades are not tested.) The tracker remains
 compatible with subprocesses that use new protocol (that
 is, subprocesses using Python 3.13.10, 3.14.1 and 3.15).
- Core and Builtins
 - gh-142218: Fix crash when inserting into a split table
 dictionary with a non str key that matches an existing key.


- Update to 3.13.10:

- Tools/Demos
 - gh-141442: The iOS testbed now correctly handles test
 arguments that contain spaces.
- Tests
 - gh-140482: Preserve and restore the state of stty echo as
 part of the test environment.
 - gh-140082: Update python -m test to set FORCE_COLOR=1 when
 being run with color enabled so that unittest which is run
 by it with redirected output will output in color.
 - gh-136442: Use exitcode 1 instead of 5 if
 unittest.TestCase.setUpClass() raises an exception
- Library
 - gh-74389: When the stdin being used by a subprocess.Popen
 instance is closed, this is now ignored in
 subprocess.Popen.communicate() instead of leaving the class
 in an inconsistent state.
 - gh-87512: Fix subprocess.Popen.communicate() timeout
 handling on Windows when writing large input. Previously,
 the timeout was ignored during stdin writing, causing the
 method to block indefinitely if the child process did not
 consume input quickly. The stdin write is now performed in
 a background thread, allowing the timeout to be properly
 enforced.
 - gh-141473: When subprocess.Popen.communicate() was called
 with input and a timeout and is called for a second time
 after a TimeoutExpired exception before ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'python313' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpython3_13-1_0", rpm:"libpython3_13-1_0~3.13.11~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_13-1_0-x86-64-v3", rpm:"libpython3_13-1_0-x86-64-v3~3.13.11~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python313", rpm:"python313~3.13.11~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python313-base", rpm:"python313-base~3.13.11~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python313-base-x86-64-v3", rpm:"python313-base-x86-64-v3~3.13.11~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python313-curses", rpm:"python313-curses~3.13.11~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python313-dbm", rpm:"python313-dbm~3.13.11~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python313-devel", rpm:"python313-devel~3.13.11~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python313-doc", rpm:"python313-doc~3.13.11~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python313-doc-devhelp", rpm:"python313-doc-devhelp~3.13.11~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python313-idle", rpm:"python313-idle~3.13.11~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python313-tk", rpm:"python313-tk~3.13.11~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python313-tools", rpm:"python313-tools~3.13.11~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python313-x86-64-v3", rpm:"python313-x86-64-v3~3.13.11~160000.1.1", rls:"SLES16.0.0"))) {
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
