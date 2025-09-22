# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122760");
  script_cve_id("CVE-2013-1752", "CVE-2013-1753", "CVE-2014-4616", "CVE-2014-4650", "CVE-2014-7185");
  script_tag(name:"creation_date", value:"2015-11-24 08:17:32 +0000 (Tue, 24 Nov 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-26 13:49:00 +0000 (Wed, 26 Feb 2020)");

  script_name("Oracle: Security Advisory (ELSA-2015-2101)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-2101");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-2101.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python' package(s) announced via the ELSA-2015-2101 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.7.5-34.0.1]
- Add Oracle Linux distribution in platform.py [orabug 20812544]

[2.7.5-34]
- Revert fix for rhbz#1117751 as it leads to regressions
Resolves: rhbz#1117751

[2.7.5-33]
- Only restore SIG_PIPE when Popen called with restore_sigpipe
Resolves: rhbz#1117751

[2.7.5-32]
- Backport SSLSocket.version function
- Temporary disable test_gdb on ppc64le rhbz#1260558
Resolves: rhbz#1259421

[2.7.5-31]
- Update load_cert_chain function to accept None keyfile
Resolves: rhbz#1250611

[2.7.5-30]
- Change Patch224 according to latest update in PEP493
Resolves:rhbz#1219108

[2.7.5-29]
- Popen shouldn't ignore SIG_PIPE
Resolves: rhbz#1117751

[2.7.5-28]
- Exclude python subprocess temp files from cleaning
Resolves: rhbz#1058482

[2.7.5-27]
- Add list for cprofile sort option
Resolves:rhbz#1237107

[2.7.5-26]
- Add switch to toggle cert verification on or off globally
Resolves:rhbz#1219108

[2.7.5-25]
- PEP476 enable cert verifications by default
Resolves:rhbz#1219110

[2.7.5-24]
- Massive backport of ssl module from python3 aka PEP466
Resolves: rhbz#1111461

[2.7.5-23]
- Fixed CVE-2013-1753, CVE-2013-1752, CVE-2014-4616, CVE-2014-4650, CVE-2014-7185
Resolves: rhbz#1206574

[2.7.5-22]
- Fix importing readline producing erroneous output
Resolves: rhbz#1189301

[2.7.5-21]
- Add missing import in bdist_rpm
Resolves: rhbz#1177613

[2.7.5-20]
- Avoid double close of subprocess pipes
Resolves: rhbz#1103452

[2.7.5-19]
- make multiprocessing ignore EINTR
Resolves: rhbz#1181624");

  script_tag(name:"affected", value:"'python' package(s) on Oracle Linux 7.");

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

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"python", rpm:"python~2.7.5~34.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-debug", rpm:"python-debug~2.7.5~34.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-devel", rpm:"python-devel~2.7.5~34.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libs", rpm:"python-libs~2.7.5~34.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-test", rpm:"python-test~2.7.5~34.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tools", rpm:"python-tools~2.7.5~34.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tkinter", rpm:"tkinter~2.7.5~34.0.1.el7", rls:"OracleLinux7"))) {
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
