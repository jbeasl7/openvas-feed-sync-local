# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123515");
  script_cve_id("CVE-2013-4238");
  script_tag(name:"creation_date", value:"2015-10-06 11:04:55 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Oracle: Security Advisory (ELSA-2013-1582)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-1582");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-1582.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python' package(s) announced via the ELSA-2013-1582 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.6-51]
- Fixed memory leak in _ssl._get_peer_alt_names
Resolves: rhbz#1002983

[2.6.6-50]
- Added fix for CVE-2013-4238
Resolves: rhbz#998784

[2.6.6-49]
- Fix shebangs in several files in python-tools subpackage
Resolves: rhbz#521898

[2.6.6-48]
- Fix sqlite3.Cursor.lastrowid under a Turkish locale.
Resolves: rhbz#841937

[2.6.6-47]
- Urlparse now parses query and fragment of urls for any scheme.
Resolves: rhbz#978129

[2.6.6-46]
- Add wrapper for select.select to restart a system call
Resolves: rhbz#948025

[2.6.6-45]
- Add try-except to catch OSError in WatchedFileHandler
Resolves: rhbz#919163

[2.6.6-44]
- Fix urandom to throw proper exception
Resolves: rhbz#893034

[2.6.6-43]
- Backport of collections.OrderedDict from Python 2.7
Resolves: rhbz#929258

[2.6.6-42]
- Add an explicit RPATH to _elementtree.so pointing at the directory
containing system expat
Resolves: rhbz#962779

[2.6.6-41]
- Don't let failed incoming SSL connection stay open forever
Resolves: rhbz#960168

[2.6.6-40]
- Fix Python not reading Alternative Subject Names from some SSL
certificates
Resolves: rhbz#928390

[2.6.6-39]
- Remove BOM insertion code from SysLogHandler that causes messages to be
treated as EMERG level
Resolves: rhbz#845802

[2.6.6-38]
- move most of the payload of the core package to the libs subpackage, given
that the libs aren't meaningfully usable without the standard libraries
- preserve timestamps when fixing shebangs (patch 158) and when installing,
to minimize .pyc/.pyo differences across architectures (due to the embedded
mtime in .pyc/.pyo headers)
- fix multilib issue in /usr/bin/modulator and /usr/bin/pynche
Related: rhbz#958256");

  script_tag(name:"affected", value:"'python' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"python", rpm:"python~2.6.6~51.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-devel", rpm:"python-devel~2.6.6~51.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libs", rpm:"python-libs~2.6.6~51.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-test", rpm:"python-test~2.6.6~51.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tools", rpm:"python-tools~2.6.6~51.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tkinter", rpm:"tkinter~2.6.6~51.el6", rls:"OracleLinux6"))) {
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
