# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123873");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2012-1711", "CVE-2012-1713", "CVE-2012-1716", "CVE-2012-1717", "CVE-2012-1718", "CVE-2012-1719", "CVE-2012-1723", "CVE-2012-1724", "CVE-2012-1725", "CVE-2012-1726");
  script_tag(name:"creation_date", value:"2015-10-06 11:09:41 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:38:00 +0000 (Tue, 16 Jul 2024)");

  script_name("Oracle: Security Advisory (ELSA-2012-1009)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-1009");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-1009.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.7.0-openjdk' package(s) announced via the ELSA-2012-1009 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.7.0.5-2.2.1.0.1.el6]
- Modify DISTRO_NAME for Oracle

[1.7.0.5-2.2.1.el6]
- Updated priority to be > 17000 and to depend on buildver variable
- Variable buildver increased to 5 as it should be
- Resolves: rhbz#828759

[1.7.0.3-2.2.1.el6]
- Used newly prepared tarball with security fixes
- Bump to icedtea7-forest-2.2.1
- _mandir/man1/jcmd-name.1 added to alternatives
- Updated rhino.patch
- Updated java-1.7.0-openjdk-java-access-bridge-security.patch
- Modified partially upstreamed patch302 - systemtap.patch
- Temporarily disabled patch102 - java-1.7.0-openjdk-size_t.patch
- Removed already upstreamed patches 104,108,109,301,110:
 - java-1.7.0-openjdk-arm-ftbfs.patch
 - java-1.7.0-openjdk-system-zlib.patch
 - java-1.7.0-openjdk-remove-mimpure-opt.patch
 - systemtap-alloc-size-workaround.patch
 - java-1.7.0-fix-gio-detection.patch
- Access gnome bridge jar forced to be 644
- Added patch303 - java-1.7.0-openjdk-jstack.patch which resolved RH804632 for openjdk6
- Resolves: rhbz#828759");

  script_tag(name:"affected", value:"'java-1.7.0-openjdk' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk", rpm:"java-1.7.0-openjdk~1.7.0.5~2.2.1.0.1.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-demo", rpm:"java-1.7.0-openjdk-demo~1.7.0.5~2.2.1.0.1.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-devel", rpm:"java-1.7.0-openjdk-devel~1.7.0.5~2.2.1.0.1.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-javadoc", rpm:"java-1.7.0-openjdk-javadoc~1.7.0.5~2.2.1.0.1.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-src", rpm:"java-1.7.0-openjdk-src~1.7.0.5~2.2.1.0.1.el6_3", rls:"OracleLinux6"))) {
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
