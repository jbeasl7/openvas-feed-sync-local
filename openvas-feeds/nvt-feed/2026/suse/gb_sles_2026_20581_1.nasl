# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20581.1");
  script_cve_id("CVE-2025-11468", "CVE-2025-15282", "CVE-2026-0672", "CVE-2026-0865", "CVE-2026-1299");
  script_tag(name:"creation_date", value:"2026-03-09 04:38:35 +0000 (Mon, 09 Mar 2026)");
  script_version("2026-03-10T10:15:11+0000");
  script_tag(name:"last_modification", value:"2026-03-10 10:15:11 +0000 (Tue, 10 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20581-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20581-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620581-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257029");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257031");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257046");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257181");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024622.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python313' package(s) announced via the SUSE-SU-2026:20581-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python313 fixes the following issues:

Update to version 3.13.12.

Security issues fixed:

- CVE-2025-11468: header injection when folding a long comment in an email header containing exclusively unfoldable
 characters (bsc#1257029).
- CVE-2025-15282: user-controlled data URLs parsed may allow injecting headers (bsc#1257046).
- CVE-2026-0672: HTTP header injection via user-controlled cookie values and parameters when using http.cookies.Morsel
 (bsc#1257031).
- CVE-2026-0865: user-controlled header containing newlines can allow injecting HTTP headers (bsc#1257042).
- CVE-2026-1299: header injection when an email is serialized due to improper newline quoting in `BytesGenerator`
 (bsc#1257181).

Other updates and bugfixes:

- Update to version 3.13.12.

 - Library

 - gh-144380: Improve performance of io.BufferedReader line
 iteration by ~49%.
 - gh-144169: Fix three crashes when non-string keyword
 arguments are supplied to objects in the ast module.
 - gh-144100: Fixed a crash in ctypes when using a deprecated
 POINTER(str) type in argtypes. Instead of aborting, ctypes
 now raises a proper Python exception when the pointer
 target type is unresolved.
 - gh-144050: Fix stat.filemode() in the pure-Python
 implementation to avoid misclassifying invalid mode values
 as block devices.
 - gh-144023: Fixed validation of file descriptor 0 in posix
 functions when used with follow_symlinks parameter.
 - gh-143999: Fix an issue where inspect.getgeneratorstate()
 and inspect.getcoroutinestate() could fail for generators
 wrapped by types.coroutine() in the suspended state.
 - gh-143706: Fix multiprocessing forkserver so that sys.argv
 is correctly set before __main__ is preloaded. Previously,
 sys.argv was empty during main module import in forkserver
 child processes. This fixes a regression introduced in
 3.13.8 and 3.14.1. Root caused by Aaron Wieczorek, test
 provided by Thomas Watson, thanks!
 - gh-143638: Forbid reentrant calls of the pickle.Pickler and
 pickle.Unpickler methods for the C implementation.
 Previously, this could cause crash or data corruption, now
 concurrent calls of methods of the same object raise
 RuntimeError.
 - gh-78724: Raise RuntimeError's when user attempts to call
 methods on half-initialized Struct objects, For example,
 created by Struct.__new__(Struct). Patch by Sergey
 B Kirpichev.
 - gh-143602: Fix a inconsistency issue in write() that leads
 to unexpected buffer overwrite by deduplicating the buffer
 exports.
 - gh-143547: Fix sys.unraisablehook() when the hook raises an
 exception and changes sys.unraisablehook(): hold a strong
 reference to the old hook. Patch by Victor Stinner.
 - gh-143378: Fix use-after-free crashes when a BytesIO object
 is concurrently mutated during write() or writelines().
 - gh-143346: Fix incorrect wrapping of the Base64 data in
 plistlib._PlistWriter when the indent contains a mix of
 tabs and ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"libpython3_13-1_0", rpm:"libpython3_13-1_0~3.13.12~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_13-1_0-x86-64-v3", rpm:"libpython3_13-1_0-x86-64-v3~3.13.12~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python313", rpm:"python313~3.13.12~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python313-base", rpm:"python313-base~3.13.12~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python313-base-x86-64-v3", rpm:"python313-base-x86-64-v3~3.13.12~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python313-curses", rpm:"python313-curses~3.13.12~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python313-dbm", rpm:"python313-dbm~3.13.12~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python313-devel", rpm:"python313-devel~3.13.12~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python313-doc", rpm:"python313-doc~3.13.12~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python313-doc-devhelp", rpm:"python313-doc-devhelp~3.13.12~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python313-idle", rpm:"python313-idle~3.13.12~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python313-tk", rpm:"python313-tk~3.13.12~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python313-tools", rpm:"python313-tools~3.13.12~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python313-x86-64-v3", rpm:"python313-x86-64-v3~3.13.12~160000.1.1", rls:"SLES16.0.0"))) {
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
