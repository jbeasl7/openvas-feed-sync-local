# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123066");
  script_cve_id("CVE-2013-1752", "CVE-2014-1912", "CVE-2014-4650", "CVE-2014-7185");
  script_tag(name:"creation_date", value:"2015-10-06 10:58:55 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-26 13:49:00 +0000 (Wed, 26 Feb 2020)");

  script_name("Oracle: Security Advisory (ELSA-2015-1330)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1330");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1330.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python' package(s) announced via the ELSA-2015-1330 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.6-64.0.1]
- Add Oracle Linux distribution in platform.py [orabug 21288328] (Keshav Sharma)

[2.6.6-64]
- Enable use of deepcopy() with instance methods
Resolves: rhbz#1223037

[2.6.6-63]
- Since -libs now provide python-ordered dict, added ordereddict
 dist-info to site-packages
Resolves: rhbz#1199997

[2.6.6-62]
- Fix CVE-2014-7185/4650/1912 CVE-2013-1752
Resolves: rhbz#1206572

[2.6.6-61]
- Fix logging module error when multiprocessing module is not initialized
Resolves: rhbz#1204966

[2.6.6-60]
- Add provides for python-ordereddict
Resolves: rhbz#1199997

[2.6.6-59]
- Let ConfigParse handle options without values
- Add check phase to specfile, fix and skip relevant failing tests
Resolves: rhbz#1031709

[2.6.6-58]
- Make Popen.communicate catch EINTR error
Resolves: rhbz#1073165

[2.6.6-57]
- Add choices for sort option of cProfile for better output
Resolves: rhbz#1160640

[2.6.6-56]
- Make multiprocessing ignore EINTR
Resolves: rhbz#1180864

[2.6.6-55]
- Fix iteration over files with very long lines
Resolves: rhbz#794632

[2.6.6-54]
- Fix subprocess.Popen.communicate() being broken by SIGCHLD handler.
Resolves: rhbz#1065537
- Rebuild against latest valgrind-devel.
Resolves: rhbz#1142170

[2.6.6-53]
- Bump release up to ensure proper upgrade path.
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

  if(!isnull(res = isrpmvuln(pkg:"python", rpm:"python~2.6.6~64.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-devel", rpm:"python-devel~2.6.6~64.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libs", rpm:"python-libs~2.6.6~64.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-test", rpm:"python-test~2.6.6~64.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tools", rpm:"python-tools~2.6.6~64.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tkinter", rpm:"tkinter~2.6.6~64.0.1.el6", rls:"OracleLinux6"))) {
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
