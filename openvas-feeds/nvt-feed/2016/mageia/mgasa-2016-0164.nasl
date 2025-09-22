# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131288");
  script_cve_id("CVE-2016-3674");
  script_tag(name:"creation_date", value:"2016-05-09 11:17:51 +0000 (Mon, 09 May 2016)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-23 17:54:18 +0000 (Fri, 23 May 2025)");

  script_name("Mageia: Security Advisory (MGASA-2016-0164)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0164");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0164.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18277");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2016-April/183180.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'javapackages-tools, xstream' package(s) announced via the MGASA-2016-0164 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated xstream packages fix security vulnerability:

XStream (x-stream.github.io) is a Java library to marshal Java objects into XML
and back. For this purpose it supports a lot of different XML parsers. Some of
those can also process external entities which was enabled by default. An
attacker could therefore provide manipulated XML as input to access data on the
file system (CVE-2016-3674).");

  script_tag(name:"affected", value:"'javapackages-tools, xstream' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"ivy-local", rpm:"ivy-local~4.1.0~15.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"javapackages-local", rpm:"javapackages-local~4.1.0~15.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"javapackages-tools", rpm:"javapackages-tools~4.1.0~15.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"javapackages-tools-doc", rpm:"javapackages-tools-doc~4.1.0~15.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-local", rpm:"maven-local~4.1.0~15.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-javapackages", rpm:"python-javapackages~4.1.0~15.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xstream", rpm:"xstream~1.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xstream-benchmark", rpm:"xstream-benchmark~1.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xstream-hibernate", rpm:"xstream-hibernate~1.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xstream-javadoc", rpm:"xstream-javadoc~1.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xstream-parent", rpm:"xstream-parent~1.4.9~1.mga5", rls:"MAGEIA5"))) {
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
