# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.410193102102971101101");
  script_tag(name:"creation_date", value:"2025-02-12 04:04:54 +0000 (Wed, 12 Feb 2025)");
  script_version("2025-02-12T05:37:43+0000");
  script_tag(name:"last_modification", value:"2025-02-12 05:37:43 +0000 (Wed, 12 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-4e93ffa1ee)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-4e93ffa1ee");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-4e93ffa1ee");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-21-openjdk' package(s) announced via the FEDORA-2025-4e93ffa1ee advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"January CPU 2025");

  script_tag(name:"affected", value:"'java-21-openjdk' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk", rpm:"java-21-openjdk~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-debuginfo", rpm:"java-21-openjdk-debuginfo~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-debugsource", rpm:"java-21-openjdk-debugsource~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-demo", rpm:"java-21-openjdk-demo~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-demo-fastdebug", rpm:"java-21-openjdk-demo-fastdebug~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-demo-slowdebug", rpm:"java-21-openjdk-demo-slowdebug~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-devel", rpm:"java-21-openjdk-devel~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-devel-debuginfo", rpm:"java-21-openjdk-devel-debuginfo~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-devel-fastdebug", rpm:"java-21-openjdk-devel-fastdebug~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-devel-fastdebug-debuginfo", rpm:"java-21-openjdk-devel-fastdebug-debuginfo~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-devel-slowdebug", rpm:"java-21-openjdk-devel-slowdebug~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-devel-slowdebug-debuginfo", rpm:"java-21-openjdk-devel-slowdebug-debuginfo~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-fastdebug", rpm:"java-21-openjdk-fastdebug~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-fastdebug-debuginfo", rpm:"java-21-openjdk-fastdebug-debuginfo~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-headless", rpm:"java-21-openjdk-headless~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-headless-debuginfo", rpm:"java-21-openjdk-headless-debuginfo~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-headless-fastdebug", rpm:"java-21-openjdk-headless-fastdebug~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-headless-fastdebug-debuginfo", rpm:"java-21-openjdk-headless-fastdebug-debuginfo~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-headless-slowdebug", rpm:"java-21-openjdk-headless-slowdebug~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-headless-slowdebug-debuginfo", rpm:"java-21-openjdk-headless-slowdebug-debuginfo~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-javadoc", rpm:"java-21-openjdk-javadoc~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-javadoc-zip", rpm:"java-21-openjdk-javadoc-zip~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-jmods", rpm:"java-21-openjdk-jmods~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-jmods-fastdebug", rpm:"java-21-openjdk-jmods-fastdebug~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-jmods-slowdebug", rpm:"java-21-openjdk-jmods-slowdebug~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-slowdebug", rpm:"java-21-openjdk-slowdebug~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-slowdebug-debuginfo", rpm:"java-21-openjdk-slowdebug-debuginfo~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-src", rpm:"java-21-openjdk-src~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-src-fastdebug", rpm:"java-21-openjdk-src-fastdebug~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-src-slowdebug", rpm:"java-21-openjdk-src-slowdebug~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-static-libs", rpm:"java-21-openjdk-static-libs~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-static-libs-fastdebug", rpm:"java-21-openjdk-static-libs-fastdebug~21.0.6.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-static-libs-slowdebug", rpm:"java-21-openjdk-static-libs-slowdebug~21.0.6.0.7~1.fc40", rls:"FC40"))) {
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
