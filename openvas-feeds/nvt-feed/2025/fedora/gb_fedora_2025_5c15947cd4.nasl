# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.59915947991004");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:44+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:44 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-5c15947cd4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-5c15947cd4");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-5c15947cd4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.8.0-openjdk-portable, java-17-openjdk-portable' package(s) announced via the FEDORA-2025-5c15947cd4 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"April 2025 CPU");

  script_tag(name:"affected", value:"'java-1.8.0-openjdk-portable, java-17-openjdk-portable' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-portable", rpm:"java-1.8.0-openjdk-portable~1.8.0.452.b06~2.fc39", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-portable-devel", rpm:"java-1.8.0-openjdk-portable-devel~1.8.0.452.b06~2.fc39", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-portable-devel-fastdebug", rpm:"java-1.8.0-openjdk-portable-devel-fastdebug~1.8.0.452.b06~2.fc39", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-portable-devel-slowdebug", rpm:"java-1.8.0-openjdk-portable-devel-slowdebug~1.8.0.452.b06~2.fc39", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-portable-docs", rpm:"java-1.8.0-openjdk-portable-docs~1.8.0.452.b06~2.fc39", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-portable-fastdebug", rpm:"java-1.8.0-openjdk-portable-fastdebug~1.8.0.452.b06~2.fc39", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-portable-misc", rpm:"java-1.8.0-openjdk-portable-misc~1.8.0.452.b06~2.fc39", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-portable-slowdebug", rpm:"java-1.8.0-openjdk-portable-slowdebug~1.8.0.452.b06~2.fc39", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-portable-sources", rpm:"java-1.8.0-openjdk-portable-sources~1.8.0.452.b06~2.fc39", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-portable-unstripped", rpm:"java-1.8.0-openjdk-portable-unstripped~1.8.0.452.b06~2.fc39", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-portable", rpm:"java-17-openjdk-portable~17.0.15.0.6~1.fc40", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-portable-devel", rpm:"java-17-openjdk-portable-devel~17.0.15.0.6~1.fc40", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-portable-devel-fastdebug", rpm:"java-17-openjdk-portable-devel-fastdebug~17.0.15.0.6~1.fc40", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-portable-devel-slowdebug", rpm:"java-17-openjdk-portable-devel-slowdebug~17.0.15.0.6~1.fc40", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-portable-docs", rpm:"java-17-openjdk-portable-docs~17.0.15.0.6~1.fc40", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-portable-fastdebug", rpm:"java-17-openjdk-portable-fastdebug~17.0.15.0.6~1.fc40", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-portable-misc", rpm:"java-17-openjdk-portable-misc~17.0.15.0.6~1.fc40", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-portable-slowdebug", rpm:"java-17-openjdk-portable-slowdebug~17.0.15.0.6~1.fc40", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-portable-sources", rpm:"java-17-openjdk-portable-sources~17.0.15.0.6~1.fc40", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-portable-static-libs", rpm:"java-17-openjdk-portable-static-libs~17.0.15.0.6~1.fc40", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-portable-static-libs-fastdebug", rpm:"java-17-openjdk-portable-static-libs-fastdebug~17.0.15.0.6~1.fc40", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-portable-static-libs-slowdebug", rpm:"java-17-openjdk-portable-static-libs-slowdebug~17.0.15.0.6~1.fc40", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-portable-unstripped", rpm:"java-17-openjdk-portable-unstripped~17.0.15.0.6~1.fc40", rls:"FC41"))) {
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
