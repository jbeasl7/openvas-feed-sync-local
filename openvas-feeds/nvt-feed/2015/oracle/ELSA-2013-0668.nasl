# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123657");
  script_cve_id("CVE-2012-2677");
  script_tag(name:"creation_date", value:"2015-10-06 11:06:52 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2013-0668)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux5|OracleLinux6)");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0668");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0668.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'boost' package(s) announced via the ELSA-2013-0668 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.41.0-15]
- Add in explicit dependences between some boost subpackages

[1.41.0-14]
- Build with -fno-strict-aliasing

[1.41.0-13]
- In Boost.Pool, be careful not to overflow allocated chunk size
 (boost-1.41.0-pool.patch)

[1.41.0-12]
- Add an upstream patch that fixes computation of CRC in zlib streams.
- Resolves: #707624");

  script_tag(name:"affected", value:"'boost' package(s) on Oracle Linux 5, Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"boost", rpm:"boost~1.33.1~16.el5_9", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-devel", rpm:"boost-devel~1.33.1~16.el5_9", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-doc", rpm:"boost-doc~1.33.1~16.el5_9", rls:"OracleLinux5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"boost", rpm:"boost~1.41.0~15.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-date-time", rpm:"boost-date-time~1.41.0~15.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-devel", rpm:"boost-devel~1.41.0~15.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-doc", rpm:"boost-doc~1.41.0~15.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-filesystem", rpm:"boost-filesystem~1.41.0~15.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-graph", rpm:"boost-graph~1.41.0~15.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-graph-mpich2", rpm:"boost-graph-mpich2~1.41.0~15.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-graph-openmpi", rpm:"boost-graph-openmpi~1.41.0~15.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-iostreams", rpm:"boost-iostreams~1.41.0~15.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-math", rpm:"boost-math~1.41.0~15.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-mpich2", rpm:"boost-mpich2~1.41.0~15.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-mpich2-devel", rpm:"boost-mpich2-devel~1.41.0~15.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-mpich2-python", rpm:"boost-mpich2-python~1.41.0~15.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-openmpi", rpm:"boost-openmpi~1.41.0~15.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-openmpi-devel", rpm:"boost-openmpi-devel~1.41.0~15.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-openmpi-python", rpm:"boost-openmpi-python~1.41.0~15.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-program-options", rpm:"boost-program-options~1.41.0~15.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-python", rpm:"boost-python~1.41.0~15.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-regex", rpm:"boost-regex~1.41.0~15.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-serialization", rpm:"boost-serialization~1.41.0~15.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-signals", rpm:"boost-signals~1.41.0~15.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-static", rpm:"boost-static~1.41.0~15.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-system", rpm:"boost-system~1.41.0~15.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-test", rpm:"boost-test~1.41.0~15.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-thread", rpm:"boost-thread~1.41.0~15.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-wave", rpm:"boost-wave~1.41.0~15.el6_4", rls:"OracleLinux6"))) {
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
