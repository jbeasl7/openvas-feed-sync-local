# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.03159.1");
  script_cve_id("CVE-2024-45336", "CVE-2024-45341", "CVE-2025-0913", "CVE-2025-22866", "CVE-2025-22870", "CVE-2025-22871", "CVE-2025-4673", "CVE-2025-4674", "CVE-2025-47906", "CVE-2025-47907");
  script_tag(name:"creation_date", value:"2025-09-12 04:06:31 +0000 (Fri, 12 Sep 2025)");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:03159-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03159-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503159-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229122");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236046");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238572");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240550");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244156");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244157");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246118");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247719");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247720");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247816");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041646.html");
  script_xref(name:"URL", value:"https://pkg.go.dev/github.com/uisdevsquad/go-test/debugmate");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.23-openssl' package(s) announced via the SUSE-SU-2025:03159-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.23-openssl fixes the following issues:

Update to version 1.23.12 cut from the go1.23-fips-release branch at the revision tagged go1.23.12-1-openssl-fips. ( jsc#SLE-18320)

 * Rebase to 1.23.12
 * Fix HKDF-Extract The latest OpenSSL in c9s/c10s requires nil
 salt to be passed as a hash length buffer of zeros.

Packaging improvements:

 * Update go_bootstrap_version to go1.21 from go1.20 to shorten
 the bootstrap chain. go1.21 can optionally be bootstrapped with
 gccgo and serve as the inital version of go1.x.
 * Refs boo#1247816 bootstrap go1.21 with gccgo

go1.23.12 (released 2025-08-06) includes security fixes to the database/sql and os/exec packages, as well as bug fixes to the runtime.

CVE-2025-47906 CVE-2025-47907:
 * go#74803 go#74466 boo#1247719 security: fix CVE-2025-47906 os/exec: LookPath bug: incorrect expansion of '', '.' and '..' in some PATH configurations
 * go#74832 go#74831 boo#1247720 security: fix CVE-2025-47907 database/sql: incorrect results returned from Rows.Scan

 * go#74415 runtime: use-after-free of allpSnapshot in findRunnable
 * go#74693 runtime: segfaults in runtime.(*unwinder).next
 * go#74721 cmd/go: TestScript/build_trimpath_cgo fails to decode dwarf on release-branch.go1.23
 * go#74726 cmd/cgo/internal/testsanitizers: failures with signal: segmentation fault or exit status 66

go1.23.11 (released 2025-07-08) includes security fixes to the go command, as well as bug fixes to the compiler, the linker, and the runtime.

CVE-2025-4674:
 * go#74382 go#74380 boo#1246118 security: fix CVE-2025-4674 cmd/go: disable support for multiple vcs in one module

 * go#73907 runtime: bad frame pointer during panic during duffcopy
 * go#74289 runtime: heap mspan limit is set too late, causing data race between span allocation and conservative scanning
 * go#74293 internal/trace: stress tests triggering suspected deadlock in tracer
 * go#74362 runtime/pprof: crash 'cannot read stack of running goroutine' in goroutine profile
 * go#74402 cmd/link: duplicated definition of symbol github.com/ebitengine/purego.syscall15XABI0 when running with ASAN

go1.23.10 (released 2025-06-05) includes security fixes to the net/http and os packages, as well as bug fixes to the linker. (boo#1229122 go1.23 release tracking)

CVE-2025-0913 CVE-2025-4673:
 * go#73719 go#73612 boo#1244157 security: fix CVE-2025-0913 os: inconsistent handling of O_CREATE<pipe>O_EXCL on Unix and Windows
 * go#73905 go#73816 boo#1244156 security: fix CVE-2025-4673 net/http: sensitive headers not cleared on cross-origin redirect

 * go#73677 runtime/debug: BuildSetting does not document DefaultGODEBUG
 * go#73831 cmd/link: Go 1.24.3 and 1.23.9 regression - duplicated definition of symbol dlopen

go1.23.9 (released 2025-05-06) includes fixes to the runtime and the linker. (boo#1229122 go1.23 release tracking)

 * go#73091 cmd/link: linkname directive on userspace variable can ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'go1.23-openssl' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"go1.23-openssl", rpm:"go1.23-openssl~1.23.12~150600.13.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.23-openssl-doc", rpm:"go1.23-openssl-doc~1.23.12~150600.13.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.23-openssl-race", rpm:"go1.23-openssl-race~1.23.12~150600.13.9.1", rls:"openSUSELeap15.6"))) {
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
