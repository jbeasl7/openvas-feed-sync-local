# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122278");
  script_cve_id("CVE-2008-5983", "CVE-2009-4134", "CVE-2010-1449", "CVE-2010-1450", "CVE-2010-1634", "CVE-2010-2089");
  script_tag(name:"creation_date", value:"2015-10-06 11:15:51 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2011-0027)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-0027");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-0027.html");
  script_xref(name:"URL", value:"http://bugs.python.org/issue7082");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python' package(s) announced via the ELSA-2011-0027 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.4.3-43]
- add missing patch 206
Related: rhbz#549372

[2.4.3-42]
- fix test_pyclbr to match the urllib change in patch 204 (patch 206)
- allow the 'no_proxy' environment variable to override 'ftp_proxy' in
urllib2 (patch 207)
- fix typos in names of patches 204 and 205
Related: rhbz#549372

[2.4.3-41]
- backport support for the 'no_proxy' environment variable to the urllib and
urllib2 modules (patches 204 and 205, respectively)
Resolves: rhbz#549372

[2.4.3-40]
- backport fixes for arena allocator from 2.5a1
- disable arena allocator when run under valgrind on x86, x86_64, ppc, ppc64
(patch 203)
- add patch to add sys._debugmallocstats() hook (patch 202)
Resolves: rhbz#569093

[2.4.3-39]
- fix various flaws in the 'audioop' module
- Resolves: CVE-2010-1634 CVE-2010-2089
- backport the new PySys_SetArgvEx libpython entrypoint from 2.6
- Related: CVE-2008-5983
- restrict creation of the .relocation-tag files to i386 builds
- Related: rhbz#644761
- move the python-optik metadata from the core subpackage to the python-libs
subpackage
- Related: rhbz#625372

[2.4.3-38]
- add metadata to ensure that 'yum install python-libs' works
- Related: rhbz#625372

[2.4.3-37]
- create dummy ELF file '.relocation-tag' to force RPM directory coloring,
fixing i386 on ia64 compat
- Resolves: rhbz#644761

[2.4.3-36]
- Backport fix for [link moved to references] to 2.4.3
- Resolves: rhbz#644147

[2.4.3-35]
- Rework rgbimgmodule fix for CVE-2008-3143
- Resolves: rhbz#644425 CVE-2009-4134 CVE-2010-1449 CVE-2010-1450

[2.4.3-34]
- fix stray 'touch' command
- Related: rhbz#625372

[2.4.3-33]
- Preserve timestamps when fixing shebangs (patch 104) and when installing, to
minimize .pyc/.pyo differences across architectures (due to the embedded mtime
in .pyc/.pyo headers)
- Related: rhbz#625372

[2.4.3-32]
- introduce libs subpackage as a dependency of the core package, moving the
shared libraries and python standard libraries there
- Resolves: rhbz#625372

[2.4.3-31]
- don't use -b when applying patch 103
- Related: rhbz#263401

[2.4.3-30]
- add missing patch
- Resolves: rhbz#263401

[2.4.3-29]
- Backport Python 2.5s tarfile module (0.8.0) to 2.4.3
- Resolves: rhbz#263401

[2.4.3-28]
- Backport fix for leaking filedescriptors in subprocess error-handling path
from Python 2.6
- Resolves: rhbz#609017
- Backport usage of 'poll' within the subprocess module to 2.4.3
- Resolves: rhbz#609020");

  script_tag(name:"affected", value:"'python' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"python", rpm:"python~2.4.3~43.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-devel", rpm:"python-devel~2.4.3~43.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libs", rpm:"python-libs~2.4.3~43.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tools", rpm:"python-tools~2.4.3~43.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tkinter", rpm:"tkinter~2.4.3~43.el5", rls:"OracleLinux5"))) {
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
