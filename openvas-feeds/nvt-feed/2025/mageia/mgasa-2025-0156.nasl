# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0156");
  script_cve_id("CVE-2025-21587", "CVE-2025-30691", "CVE-2025-30698");
  script_tag(name:"creation_date", value:"2025-05-14 04:08:25 +0000 (Wed, 14 May 2025)");
  script_version("2025-05-14T05:40:11+0000");
  script_tag(name:"last_modification", value:"2025-05-14 05:40:11 +0000 (Wed, 14 May 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-15 21:15:54 +0000 (Tue, 15 Apr 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0156)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0156");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0156.html");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2025:3845");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2025:3850");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2025:3853");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2025:3856");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34206");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuapr2025.html#AppendixJAVA");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.8.0-openjdk, java-11-openjdk, java-17-openjdk, java-latest-openjdk, timezone' package(s) announced via the MGASA-2025-0156 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Better TLS connection support. (CVE-2025-21587)
Improve compiler transformations. (CVE-2025-30691)
Enhance Buffered Image handling. (CVE-2025-30698)
The updated timezone data are needed by the new Java packages.");

  script_tag(name:"affected", value:"'java-1.8.0-openjdk, java-11-openjdk, java-17-openjdk, java-latest-openjdk, timezone' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk", rpm:"java-1.8.0-openjdk~1.8.0.452.b09~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo", rpm:"java-1.8.0-openjdk-demo~1.8.0.452.b09~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo-fastdebug", rpm:"java-1.8.0-openjdk-demo-fastdebug~1.8.0.452.b09~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo-slowdebug", rpm:"java-1.8.0-openjdk-demo-slowdebug~1.8.0.452.b09~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel", rpm:"java-1.8.0-openjdk-devel~1.8.0.452.b09~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel-fastdebug", rpm:"java-1.8.0-openjdk-devel-fastdebug~1.8.0.452.b09~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel-slowdebug", rpm:"java-1.8.0-openjdk-devel-slowdebug~1.8.0.452.b09~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-fastdebug", rpm:"java-1.8.0-openjdk-fastdebug~1.8.0.452.b09~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless", rpm:"java-1.8.0-openjdk-headless~1.8.0.452.b09~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless-fastdebug", rpm:"java-1.8.0-openjdk-headless-fastdebug~1.8.0.452.b09~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless-slowdebug", rpm:"java-1.8.0-openjdk-headless-slowdebug~1.8.0.452.b09~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc", rpm:"java-1.8.0-openjdk-javadoc~1.8.0.452.b09~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc-zip", rpm:"java-1.8.0-openjdk-javadoc-zip~1.8.0.452.b09~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-openjfx", rpm:"java-1.8.0-openjdk-openjfx~1.8.0.452.b09~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-openjfx-devel", rpm:"java-1.8.0-openjdk-openjfx-devel~1.8.0.452.b09~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-openjfx-devel-fastdebug", rpm:"java-1.8.0-openjdk-openjfx-devel-fastdebug~1.8.0.452.b09~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-openjfx-devel-slowdebug", rpm:"java-1.8.0-openjdk-openjfx-devel-slowdebug~1.8.0.452.b09~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-openjfx-fastdebug", rpm:"java-1.8.0-openjdk-openjfx-fastdebug~1.8.0.452.b09~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-openjfx-slowdebug", rpm:"java-1.8.0-openjdk-openjfx-slowdebug~1.8.0.452.b09~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-slowdebug", rpm:"java-1.8.0-openjdk-slowdebug~1.8.0.452.b09~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-src", rpm:"java-1.8.0-openjdk-src~1.8.0.452.b09~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-src-fastdebug", rpm:"java-1.8.0-openjdk-src-fastdebug~1.8.0.452.b09~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-src-slowdebug", rpm:"java-1.8.0-openjdk-src-slowdebug~1.8.0.452.b09~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk", rpm:"java-11-openjdk~11.0.27.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-demo", rpm:"java-11-openjdk-demo~11.0.27.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-demo-fastdebug", rpm:"java-11-openjdk-demo-fastdebug~11.0.27.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-demo-slowdebug", rpm:"java-11-openjdk-demo-slowdebug~11.0.27.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-devel", rpm:"java-11-openjdk-devel~11.0.27.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-devel-fastdebug", rpm:"java-11-openjdk-devel-fastdebug~11.0.27.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-devel-slowdebug", rpm:"java-11-openjdk-devel-slowdebug~11.0.27.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-fastdebug", rpm:"java-11-openjdk-fastdebug~11.0.27.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-headless", rpm:"java-11-openjdk-headless~11.0.27.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-headless-fastdebug", rpm:"java-11-openjdk-headless-fastdebug~11.0.27.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-headless-slowdebug", rpm:"java-11-openjdk-headless-slowdebug~11.0.27.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-javadoc", rpm:"java-11-openjdk-javadoc~11.0.27.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-javadoc-zip", rpm:"java-11-openjdk-javadoc-zip~11.0.27.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-jmods", rpm:"java-11-openjdk-jmods~11.0.27.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-jmods-fastdebug", rpm:"java-11-openjdk-jmods-fastdebug~11.0.27.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-jmods-slowdebug", rpm:"java-11-openjdk-jmods-slowdebug~11.0.27.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-slowdebug", rpm:"java-11-openjdk-slowdebug~11.0.27.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-src", rpm:"java-11-openjdk-src~11.0.27.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-src-fastdebug", rpm:"java-11-openjdk-src-fastdebug~11.0.27.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-src-slowdebug", rpm:"java-11-openjdk-src-slowdebug~11.0.27.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-static-libs", rpm:"java-11-openjdk-static-libs~11.0.27.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-static-libs-fastdebug", rpm:"java-11-openjdk-static-libs-fastdebug~11.0.27.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-static-libs-slowdebug", rpm:"java-11-openjdk-static-libs-slowdebug~11.0.27.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk", rpm:"java-17-openjdk~17.0.15.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-demo", rpm:"java-17-openjdk-demo~17.0.15.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-demo-fastdebug", rpm:"java-17-openjdk-demo-fastdebug~17.0.15.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-demo-slowdebug", rpm:"java-17-openjdk-demo-slowdebug~17.0.15.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-devel", rpm:"java-17-openjdk-devel~17.0.15.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-devel-fastdebug", rpm:"java-17-openjdk-devel-fastdebug~17.0.15.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-devel-slowdebug", rpm:"java-17-openjdk-devel-slowdebug~17.0.15.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-fastdebug", rpm:"java-17-openjdk-fastdebug~17.0.15.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-headless", rpm:"java-17-openjdk-headless~17.0.15.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-headless-fastdebug", rpm:"java-17-openjdk-headless-fastdebug~17.0.15.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-headless-slowdebug", rpm:"java-17-openjdk-headless-slowdebug~17.0.15.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-javadoc", rpm:"java-17-openjdk-javadoc~17.0.15.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-javadoc-zip", rpm:"java-17-openjdk-javadoc-zip~17.0.15.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-jmods", rpm:"java-17-openjdk-jmods~17.0.15.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-jmods-fastdebug", rpm:"java-17-openjdk-jmods-fastdebug~17.0.15.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-jmods-slowdebug", rpm:"java-17-openjdk-jmods-slowdebug~17.0.15.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-slowdebug", rpm:"java-17-openjdk-slowdebug~17.0.15.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-src", rpm:"java-17-openjdk-src~17.0.15.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-src-fastdebug", rpm:"java-17-openjdk-src-fastdebug~17.0.15.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-src-slowdebug", rpm:"java-17-openjdk-src-slowdebug~17.0.15.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-static-libs", rpm:"java-17-openjdk-static-libs~17.0.15.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-static-libs-fastdebug", rpm:"java-17-openjdk-static-libs-fastdebug~17.0.15.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-static-libs-slowdebug", rpm:"java-17-openjdk-static-libs-slowdebug~17.0.15.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk", rpm:"java-latest-openjdk~24.0.1.0.9~1.rolling.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-demo", rpm:"java-latest-openjdk-demo~24.0.1.0.9~1.rolling.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-demo-fastdebug", rpm:"java-latest-openjdk-demo-fastdebug~24.0.1.0.9~1.rolling.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-demo-slowdebug", rpm:"java-latest-openjdk-demo-slowdebug~24.0.1.0.9~1.rolling.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-devel", rpm:"java-latest-openjdk-devel~24.0.1.0.9~1.rolling.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-devel-fastdebug", rpm:"java-latest-openjdk-devel-fastdebug~24.0.1.0.9~1.rolling.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-devel-slowdebug", rpm:"java-latest-openjdk-devel-slowdebug~24.0.1.0.9~1.rolling.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-fastdebug", rpm:"java-latest-openjdk-fastdebug~24.0.1.0.9~1.rolling.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-headless", rpm:"java-latest-openjdk-headless~24.0.1.0.9~1.rolling.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-headless-fastdebug", rpm:"java-latest-openjdk-headless-fastdebug~24.0.1.0.9~1.rolling.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-headless-slowdebug", rpm:"java-latest-openjdk-headless-slowdebug~24.0.1.0.9~1.rolling.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-javadoc", rpm:"java-latest-openjdk-javadoc~24.0.1.0.9~1.rolling.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-javadoc-zip", rpm:"java-latest-openjdk-javadoc-zip~24.0.1.0.9~1.rolling.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-jmods", rpm:"java-latest-openjdk-jmods~24.0.1.0.9~1.rolling.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-jmods-fastdebug", rpm:"java-latest-openjdk-jmods-fastdebug~24.0.1.0.9~1.rolling.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-jmods-slowdebug", rpm:"java-latest-openjdk-jmods-slowdebug~24.0.1.0.9~1.rolling.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-slowdebug", rpm:"java-latest-openjdk-slowdebug~24.0.1.0.9~1.rolling.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-src", rpm:"java-latest-openjdk-src~24.0.1.0.9~1.rolling.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-src-fastdebug", rpm:"java-latest-openjdk-src-fastdebug~24.0.1.0.9~1.rolling.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-src-slowdebug", rpm:"java-latest-openjdk-src-slowdebug~24.0.1.0.9~1.rolling.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-static-libs", rpm:"java-latest-openjdk-static-libs~24.0.1.0.9~1.rolling.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-static-libs-fastdebug", rpm:"java-latest-openjdk-static-libs-fastdebug~24.0.1.0.9~1.rolling.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-static-libs-slowdebug", rpm:"java-latest-openjdk-static-libs-slowdebug~24.0.1.0.9~1.rolling.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"timezone", rpm:"timezone~2025a~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"timezone-java", rpm:"timezone-java~2025a~1.mga9", rls:"MAGEIA9"))) {
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
