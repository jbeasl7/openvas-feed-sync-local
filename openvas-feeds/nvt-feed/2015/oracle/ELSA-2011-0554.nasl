# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122171");
  script_cve_id("CVE-2010-3493", "CVE-2011-1015", "CVE-2011-1521");
  script_tag(name:"creation_date", value:"2015-10-06 11:14:13 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2011-0554)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-0554");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-0554.html");
  script_xref(name:"URL", value:"http://www.python.org/download/releases/2.6.6/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python, python-docs' package(s) announced via the ELSA-2011-0554 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"python:
[2.6.6-20]
Resolves: CVE-2010-3493

[2.6.6-19]
Resolves: CVE-2011-1015

[2.6.6-18]
Resolves: CVE-2011-1521

[2.6.6-17]
- recompile against systemtap 1.4
Related: rhbz#569695

[2.6.6-16]
- recompile against systemtap 1.4
Related: rhbz#569695

[2.6.6-15]
- fix race condition that sometimes breaks the build with parallel make
Resolves: rhbz#690315

[2.6.6-14]
- backport pre-canned ways of salting a password to the 'crypt' module
Resolves: rhbz#681878

[2.6.6-13]
- move lib2to3/tests to the python-test subpackage
Related: rhbz#625395

[2.6.6-12]
- fix a new test in 2.6.6 that was failing on 64-bit big-endian architectures
Resolves: rhbz#677392

[2.6.6-11]
- fix incompatibility between 2.6.6 and our non-standard M2Crypto.SSL.SSLTimeoutError
Resolves: rhbz#681811

[2.6.6-10]
- add workaround for bug in rhythmbox-0.12 exposed by python 2.6.6
Resolves: rhbz#684991

[2.6.6-9]
- prevent tracebacks for the 'py-bt' gdb command on x86_64
Resolves: rhbz#639392

[2.6.6-8]
- fix a regression in 2.6.6 relative to 2.6.5 in urllib2
Resolves: rhbz#669847

[2.6.6-7]
- add an optional 'timeout' argument to the subprocess module (patch 131)
Resolves: rhbz#567229

[2.6.6-6]
- prevent _sqlite3.so being built with a redundant RPATH of _libdir (patch 130)
- remove DOS batch file 'idle.bat'
- remove shebang lines from .py files that aren't executable, and remove
executability from .py files that don't have a shebang line
Related: rhbz#634944
- add 'Obsoletes: python-ssl' to core package, as 2.6 contains the ssl module
Resolves: rhbz#529274

[2.6.6-5]
- allow the 'no_proxy' environment variable to override 'ftp_proxy' in
urllib2 (patch 128)
Resolves: rhbz#637895
- make garbage-collection assertion failures more informative (patch 129)
Resolves: rhbz#614680

[2.6.6-4]
- backport subprocess fixes to use the 'poll' system call, rather than 'select'
Resolves: rhbz#650588

[2.6.6-3]
- use an ephemeral port for IDLE, enabling multiple instances to be run
Resolves: rhbz#639222
- add systemtap static markers, tapsets, and example scripts
Resolves: rhbz#569695

[2.6.6-2]
- fix dbm.release on ppc64/s390x
Resolves: rhbz#626756
- fix missing lib2to3 test files
Resolves: rhbz#625395
- fix test.test_commands SELinux incompatibility
Resolves: rhbz#625393
- make 'pydoc -k' more robust in the face of broken modules
Resolves: rhbz#603073

[2.6.6-1]
- rebase to 2.6.6: (which contains the big whitespace cleanup of r81031)
 [link moved to references]
 - fixup patch 102, patch 11, patch 52, patch 110
 - drop upstreamed patches: patch 113 (CVE-2010-1634), patch 114
 (CVE-2010-2089), patch 115 (CVE-2008-5983), patch 116 (rhbz598564),
 patch 118 (rhbz540518)
 - add fix for upstream bug in test_posix.py introduced in 2.6.6 (patch 120)
Resolves: rhbz#627301

python-docs:

[2.6.6-2]
- rebuild

[2.6.6-1]
- rebase to 2.6.6 to track the main python package
Related: rhbz#627301");

  script_tag(name:"affected", value:"'python, python-docs' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"python", rpm:"python~2.6.6~20.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-devel", rpm:"python-devel~2.6.6~20.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-docs", rpm:"python-docs~2.6.6~2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libs", rpm:"python-libs~2.6.6~20.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-test", rpm:"python-test~2.6.6~20.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tools", rpm:"python-tools~2.6.6~20.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tkinter", rpm:"tkinter~2.6.6~20.el6", rls:"OracleLinux6"))) {
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
