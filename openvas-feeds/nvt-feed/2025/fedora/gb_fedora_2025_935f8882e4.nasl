# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.93510288821014");
  script_tag(name:"creation_date", value:"2025-02-07 04:08:51 +0000 (Fri, 07 Feb 2025)");
  script_version("2025-02-07T05:37:57+0000");
  script_tag(name:"last_modification", value:"2025-02-07 05:37:57 +0000 (Fri, 07 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-935f8882e4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-935f8882e4");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-935f8882e4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.8.0-openjdk' package(s) announced via the FEDORA-2025-935f8882e4 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"January CPU 2025");

  script_tag(name:"affected", value:"'java-1.8.0-openjdk' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk", rpm:"java-1.8.0-openjdk~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-debuginfo", rpm:"java-1.8.0-openjdk-debuginfo~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-debugsource", rpm:"java-1.8.0-openjdk-debugsource~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo", rpm:"java-1.8.0-openjdk-demo~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo-debuginfo", rpm:"java-1.8.0-openjdk-demo-debuginfo~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo-fastdebug", rpm:"java-1.8.0-openjdk-demo-fastdebug~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo-fastdebug-debuginfo", rpm:"java-1.8.0-openjdk-demo-fastdebug-debuginfo~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo-slowdebug", rpm:"java-1.8.0-openjdk-demo-slowdebug~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo-slowdebug-debuginfo", rpm:"java-1.8.0-openjdk-demo-slowdebug-debuginfo~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel", rpm:"java-1.8.0-openjdk-devel~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel-debuginfo", rpm:"java-1.8.0-openjdk-devel-debuginfo~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel-fastdebug", rpm:"java-1.8.0-openjdk-devel-fastdebug~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel-fastdebug-debuginfo", rpm:"java-1.8.0-openjdk-devel-fastdebug-debuginfo~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel-slowdebug", rpm:"java-1.8.0-openjdk-devel-slowdebug~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel-slowdebug-debuginfo", rpm:"java-1.8.0-openjdk-devel-slowdebug-debuginfo~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-fastdebug", rpm:"java-1.8.0-openjdk-fastdebug~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-fastdebug-debuginfo", rpm:"java-1.8.0-openjdk-fastdebug-debuginfo~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless", rpm:"java-1.8.0-openjdk-headless~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless-debuginfo", rpm:"java-1.8.0-openjdk-headless-debuginfo~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless-fastdebug", rpm:"java-1.8.0-openjdk-headless-fastdebug~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless-fastdebug-debuginfo", rpm:"java-1.8.0-openjdk-headless-fastdebug-debuginfo~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless-slowdebug", rpm:"java-1.8.0-openjdk-headless-slowdebug~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless-slowdebug-debuginfo", rpm:"java-1.8.0-openjdk-headless-slowdebug-debuginfo~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc", rpm:"java-1.8.0-openjdk-javadoc~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc-zip", rpm:"java-1.8.0-openjdk-javadoc-zip~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-openjfx", rpm:"java-1.8.0-openjdk-openjfx~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-openjfx-devel", rpm:"java-1.8.0-openjdk-openjfx-devel~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-openjfx-devel-fastdebug", rpm:"java-1.8.0-openjdk-openjfx-devel-fastdebug~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-openjfx-devel-slowdebug", rpm:"java-1.8.0-openjdk-openjfx-devel-slowdebug~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-openjfx-fastdebug", rpm:"java-1.8.0-openjdk-openjfx-fastdebug~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-openjfx-slowdebug", rpm:"java-1.8.0-openjdk-openjfx-slowdebug~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-slowdebug", rpm:"java-1.8.0-openjdk-slowdebug~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-slowdebug-debuginfo", rpm:"java-1.8.0-openjdk-slowdebug-debuginfo~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-src", rpm:"java-1.8.0-openjdk-src~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-src-fastdebug", rpm:"java-1.8.0-openjdk-src-fastdebug~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-src-slowdebug", rpm:"java-1.8.0-openjdk-src-slowdebug~1.8.0.442.b06~1.fc40", rls:"FC40"))) {
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
