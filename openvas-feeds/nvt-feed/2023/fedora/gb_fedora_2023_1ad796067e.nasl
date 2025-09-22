# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885403");
  script_tag(name:"creation_date", value:"2023-12-06 02:14:55 +0000 (Wed, 06 Dec 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2023-1ad796067e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-1ad796067e");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-1ad796067e");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-latest-openjdk' package(s) announced via the FEDORA-2023-1ad796067e advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"updated to OpenJDK 21.0.1 (2023-10-17)");

  script_tag(name:"affected", value:"'java-latest-openjdk' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk", rpm:"java-latest-openjdk~21.0.1.0.12~1.rolling.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-demo", rpm:"java-latest-openjdk-demo~21.0.1.0.12~1.rolling.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-demo-fastdebug", rpm:"java-latest-openjdk-demo-fastdebug~21.0.1.0.12~1.rolling.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-demo-slowdebug", rpm:"java-latest-openjdk-demo-slowdebug~21.0.1.0.12~1.rolling.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-devel", rpm:"java-latest-openjdk-devel~21.0.1.0.12~1.rolling.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-devel-fastdebug", rpm:"java-latest-openjdk-devel-fastdebug~21.0.1.0.12~1.rolling.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-devel-slowdebug", rpm:"java-latest-openjdk-devel-slowdebug~21.0.1.0.12~1.rolling.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-fastdebug", rpm:"java-latest-openjdk-fastdebug~21.0.1.0.12~1.rolling.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-headless", rpm:"java-latest-openjdk-headless~21.0.1.0.12~1.rolling.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-headless-fastdebug", rpm:"java-latest-openjdk-headless-fastdebug~21.0.1.0.12~1.rolling.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-headless-slowdebug", rpm:"java-latest-openjdk-headless-slowdebug~21.0.1.0.12~1.rolling.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-javadoc", rpm:"java-latest-openjdk-javadoc~21.0.1.0.12~1.rolling.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-javadoc-zip", rpm:"java-latest-openjdk-javadoc-zip~21.0.1.0.12~1.rolling.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-jmods", rpm:"java-latest-openjdk-jmods~21.0.1.0.12~1.rolling.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-jmods-fastdebug", rpm:"java-latest-openjdk-jmods-fastdebug~21.0.1.0.12~1.rolling.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-jmods-slowdebug", rpm:"java-latest-openjdk-jmods-slowdebug~21.0.1.0.12~1.rolling.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-slowdebug", rpm:"java-latest-openjdk-slowdebug~21.0.1.0.12~1.rolling.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-src", rpm:"java-latest-openjdk-src~21.0.1.0.12~1.rolling.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-src-fastdebug", rpm:"java-latest-openjdk-src-fastdebug~21.0.1.0.12~1.rolling.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-src-slowdebug", rpm:"java-latest-openjdk-src-slowdebug~21.0.1.0.12~1.rolling.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-static-libs", rpm:"java-latest-openjdk-static-libs~21.0.1.0.12~1.rolling.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-static-libs-fastdebug", rpm:"java-latest-openjdk-static-libs-fastdebug~21.0.1.0.12~1.rolling.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-latest-openjdk-static-libs-slowdebug", rpm:"java-latest-openjdk-static-libs-slowdebug~21.0.1.0.12~1.rolling.fc39", rls:"FC39"))) {
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
