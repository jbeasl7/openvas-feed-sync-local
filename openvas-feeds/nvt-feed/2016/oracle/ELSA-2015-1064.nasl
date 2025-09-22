# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122870");
  script_cve_id("CVE-2013-1752", "CVE-2013-1753", "CVE-2014-1912", "CVE-2014-4616", "CVE-2014-4650", "CVE-2014-7185");
  script_tag(name:"creation_date", value:"2016-02-05 12:01:39 +0000 (Fri, 05 Feb 2016)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-26 13:49:00 +0000 (Wed, 26 Feb 2020)");

  script_name("Oracle: Security Advisory (ELSA-2015-1064)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux6|OracleLinux7)");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1064");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1064.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python27, python27-python, python27-python-pip, python27-python-setuptools, python27-python-simplejson, python27-python-wheel' package(s) announced via the ELSA-2015-1064 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"python27
[1.1-17]
- Require python-pip and python-wheel (note: in rh-python34
 this is not necessary, because 'python' depends on these).

python27-python
[2.7.8-3]
- Add httplib fix for CVE-2013-1752
Resolves: rhbz#1187779

[2.7.8-2]
- Fix %check
unset DISPLAY
 section not failing properly on failed test
- Fixed CVE-2013-1752, CVE-2013-1753
Resolves: rhbz#1187779

[2.7.8-1]
- Update to 2.7.8.
Resolves: rhbz#1167912
- Make python-devel depend on scl-utils-build.
Resolves: rhbz#1170993

python27-python-pip
 - New Package added

python27-python-setup tools
[0.9.8-3]
- Enhance patch restoring proxy support in SSL connections
Resolves: rhbz#1222507

python27-python-simplejson
[3.2.0-2]
- Fix CVE-2014-461, add boundary checks
Resolves: rhbz#1222534

python27-python-wheel
 - New Package added");

  script_tag(name:"affected", value:"'python27, python27-python, python27-python-pip, python27-python-setuptools, python27-python-simplejson, python27-python-wheel' package(s) on Oracle Linux 6, Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"python27", rpm:"python27~1.1~17.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-python", rpm:"python27-python~2.7.8~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-python-debug", rpm:"python27-python-debug~2.7.8~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-python-devel", rpm:"python27-python-devel~2.7.8~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-python-libs", rpm:"python27-python-libs~2.7.8~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-python-pip", rpm:"python27-python-pip~1.5.6~5.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-python-setuptools", rpm:"python27-python-setuptools~0.9.8~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-python-simplejson", rpm:"python27-python-simplejson~3.2.0~2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-python-test", rpm:"python27-python-test~2.7.8~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-python-tools", rpm:"python27-python-tools~2.7.8~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-python-wheel", rpm:"python27-python-wheel~0.24.0~2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-runtime", rpm:"python27-runtime~1.1~17.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-scldevel", rpm:"python27-scldevel~1.1~17.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-tkinter", rpm:"python27-tkinter~2.7.8~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"python27", rpm:"python27~1.1~20.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-python", rpm:"python27-python~2.7.8~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-python-debug", rpm:"python27-python-debug~2.7.8~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-python-devel", rpm:"python27-python-devel~2.7.8~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-python-libs", rpm:"python27-python-libs~2.7.8~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-python-pip", rpm:"python27-python-pip~1.5.6~5.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-python-setuptools", rpm:"python27-python-setuptools~0.9.8~5.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-python-simplejson", rpm:"python27-python-simplejson~3.2.0~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-python-test", rpm:"python27-python-test~2.7.8~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-python-tools", rpm:"python27-python-tools~2.7.8~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-python-wheel", rpm:"python27-python-wheel~0.24.0~2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-runtime", rpm:"python27-runtime~1.1~20.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-scldevel", rpm:"python27-scldevel~1.1~20.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-tkinter", rpm:"python27-tkinter~2.7.8~3.el7", rls:"OracleLinux7"))) {
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
