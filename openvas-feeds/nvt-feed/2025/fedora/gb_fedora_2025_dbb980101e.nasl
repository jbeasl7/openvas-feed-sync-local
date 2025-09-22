# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.1009898980101101");
  script_tag(name:"creation_date", value:"2025-07-25 04:17:17 +0000 (Fri, 25 Jul 2025)");
  script_version("2025-07-25T05:44:05+0000");
  script_tag(name:"last_modification", value:"2025-07-25 05:44:05 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-dbb980101e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-dbb980101e");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-dbb980101e");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-21-openjdk, java-25-openjdk, java-latest-openjdk' package(s) announced via the FEDORA-2025-dbb980101e advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"security update for July CPU 2025");

  script_tag(name:"affected", value:"'java-21-openjdk, java-25-openjdk, java-latest-openjdk' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk", rpm:"java-21-openjdk~21.0.8.0.9~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-debugsource", rpm:"java-21-openjdk-debugsource~21.0.8.0.9~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-demo", rpm:"java-21-openjdk-demo~21.0.8.0.9~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-demo-fastdebug", rpm:"java-21-openjdk-demo-fastdebug~21.0.8.0.9~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-demo-slowdebug", rpm:"java-21-openjdk-demo-slowdebug~21.0.8.0.9~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-devel", rpm:"java-21-openjdk-devel~21.0.8.0.9~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-devel-fastdebug", rpm:"java-21-openjdk-devel-fastdebug~21.0.8.0.9~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-devel-slowdebug", rpm:"java-21-openjdk-devel-slowdebug~21.0.8.0.9~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-fastdebug", rpm:"java-21-openjdk-fastdebug~21.0.8.0.9~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-headless", rpm:"java-21-openjdk-headless~21.0.8.0.9~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-headless-debuginfo", rpm:"java-21-openjdk-headless-debuginfo~21.0.8.0.9~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-headless-fastdebug", rpm:"java-21-openjdk-headless-fastdebug~21.0.8.0.9~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-headless-slowdebug", rpm:"java-21-openjdk-headless-slowdebug~21.0.8.0.9~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-javadoc", rpm:"java-21-openjdk-javadoc~21.0.8.0.9~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-javadoc-zip", rpm:"java-21-openjdk-javadoc-zip~21.0.8.0.9~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-jmods", rpm:"java-21-openjdk-jmods~21.0.8.0.9~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-jmods-fastdebug", rpm:"java-21-openjdk-jmods-fastdebug~21.0.8.0.9~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-jmods-slowdebug", rpm:"java-21-openjdk-jmods-slowdebug~21.0.8.0.9~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-slowdebug", rpm:"java-21-openjdk-slowdebug~21.0.8.0.9~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-src", rpm:"java-21-openjdk-src~21.0.8.0.9~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-src-fastdebug", rpm:"java-21-openjdk-src-fastdebug~21.0.8.0.9~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-src-slowdebug", rpm:"java-21-openjdk-src-slowdebug~21.0.8.0.9~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-static-libs", rpm:"java-21-openjdk-static-libs~21.0.8.0.9~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-static-libs-fastdebug", rpm:"java-21-openjdk-static-libs-fastdebug~21.0.8.0.9~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-static-libs-slowdebug", rpm:"java-21-openjdk-static-libs-slowdebug~21.0.8.0.9~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-25-openjdk", rpm:"java-25-openjdk~25.0.0.0.32~0.1.ea.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-25-openjdk-debugsource", rpm:"java-25-openjdk-debugsource~25.0.0.0.32~0.1.ea.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-25-openjdk-demo", rpm:"java-25-openjdk-demo~25.0.0.0.32~0.1.ea.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-25-openjdk-demo-fastdebug", rpm:"java-25-openjdk-demo-fastdebug~25.0.0.0.32~0.1.ea.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-25-openjdk-demo-slowdebug", rpm:"java-25-openjdk-demo-slowdebug~25.0.0.0.32~0.1.ea.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-25-openjdk-devel", rpm:"java-25-openjdk-devel~25.0.0.0.32~0.1.ea.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-25-openjdk-devel-fastdebug", rpm:"java-25-openjdk-devel-fastdebug~25.0.0.0.32~0.1.ea.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-25-openjdk-devel-slowdebug", rpm:"java-25-openjdk-devel-slowdebug~25.0.0.0.32~0.1.ea.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-25-openjdk-fastdebug", rpm:"java-25-openjdk-fastdebug~25.0.0.0.32~0.1.ea.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-25-openjdk-headless", rpm:"java-25-openjdk-headless~25.0.0.0.32~0.1.ea.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-25-openjdk-headless-debuginfo", rpm:"java-25-openjdk-headless-debuginfo~25.0.0.0.32~0.1.ea.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-25-openjdk-headless-fastdebug", rpm:"java-25-openjdk-headless-fastdebug~25.0.0.0.32~0.1.ea.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-25-openjdk-headless-slowdebug", rpm:"java-25-openjdk-headless-slowdebug~25.0.0.0.32~0.1.ea.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-25-openjdk-javadoc", rpm:"java-25-openjdk-javadoc~25.0.0.0.32~0.1.ea.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-25-openjdk-javadoc-zip", rpm:"java-25-openjdk-javadoc-zip~25.0.0.0.32~0.1.ea.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-25-openjdk-jmods", rpm:"java-25-openjdk-jmods~25.0.0.0.32~0.1.ea.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-25-openjdk-jmods-fastdebug", rpm:"java-25-openjdk-jmods-fastdebug~25.0.0.0.32~0.1.ea.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-25-openjdk-jmods-slowdebug", rpm:"java-25-openjdk-jmods-slowdebug~25.0.0.0.32~0.1.ea.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-25-openjdk-slowdebug", rpm:"java-25-openjdk-slowdebug~25.0.0.0.32~0.1.ea.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-25-openjdk-src", rpm:"java-25-openjdk-src~25.0.0.0.32~0.1.ea.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-25-openjdk-src-fastdebug", rpm:"java-25-openjdk-src-fastdebug~25.0.0.0.32~0.1.ea.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-25-openjdk-src-slowdebug", rpm:"java-25-openjdk-src-slowdebug~25.0.0.0.32~0.1.ea.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-25-openjdk-static-libs", rpm:"java-25-openjdk-static-libs~25.0.0.0.32~0.1.ea.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-25-openjdk-static-libs-fastdebug", rpm:"java-25-openjdk-static-libs-fastdebug~25.0.0.0.32~0.1.ea.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-25-openjdk-static-libs-slowdebug", rpm:"java-25-openjdk-static-libs-slowdebug~25.0.0.0.32~0.1.ea.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk", rpm:"java-latest-openjdk~24.0.2.0.12~1.rolling.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-debugsource", rpm:"java-latest-openjdk-debugsource~24.0.2.0.12~1.rolling.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-demo", rpm:"java-latest-openjdk-demo~24.0.2.0.12~1.rolling.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-demo-fastdebug", rpm:"java-latest-openjdk-demo-fastdebug~24.0.2.0.12~1.rolling.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-demo-slowdebug", rpm:"java-latest-openjdk-demo-slowdebug~24.0.2.0.12~1.rolling.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-devel", rpm:"java-latest-openjdk-devel~24.0.2.0.12~1.rolling.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-devel-fastdebug", rpm:"java-latest-openjdk-devel-fastdebug~24.0.2.0.12~1.rolling.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-devel-slowdebug", rpm:"java-latest-openjdk-devel-slowdebug~24.0.2.0.12~1.rolling.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-fastdebug", rpm:"java-latest-openjdk-fastdebug~24.0.2.0.12~1.rolling.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-headless", rpm:"java-latest-openjdk-headless~24.0.2.0.12~1.rolling.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-headless-debuginfo", rpm:"java-latest-openjdk-headless-debuginfo~24.0.2.0.12~1.rolling.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-headless-fastdebug", rpm:"java-latest-openjdk-headless-fastdebug~24.0.2.0.12~1.rolling.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-headless-slowdebug", rpm:"java-latest-openjdk-headless-slowdebug~24.0.2.0.12~1.rolling.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-javadoc", rpm:"java-latest-openjdk-javadoc~24.0.2.0.12~1.rolling.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-javadoc-zip", rpm:"java-latest-openjdk-javadoc-zip~24.0.2.0.12~1.rolling.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-jmods", rpm:"java-latest-openjdk-jmods~24.0.2.0.12~1.rolling.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-jmods-fastdebug", rpm:"java-latest-openjdk-jmods-fastdebug~24.0.2.0.12~1.rolling.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-jmods-slowdebug", rpm:"java-latest-openjdk-jmods-slowdebug~24.0.2.0.12~1.rolling.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-slowdebug", rpm:"java-latest-openjdk-slowdebug~24.0.2.0.12~1.rolling.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-src", rpm:"java-latest-openjdk-src~24.0.2.0.12~1.rolling.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-src-fastdebug", rpm:"java-latest-openjdk-src-fastdebug~24.0.2.0.12~1.rolling.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-src-slowdebug", rpm:"java-latest-openjdk-src-slowdebug~24.0.2.0.12~1.rolling.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-static-libs", rpm:"java-latest-openjdk-static-libs~24.0.2.0.12~1.rolling.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-static-libs-fastdebug", rpm:"java-latest-openjdk-static-libs-fastdebug~24.0.2.0.12~1.rolling.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-static-libs-slowdebug", rpm:"java-latest-openjdk-static-libs-slowdebug~24.0.2.0.12~1.rolling.fc41", rls:"FC41"))) {
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
