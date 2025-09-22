# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0097");
  script_cve_id("CVE-2013-7262");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0097)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0097");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0097.html");
  script_xref(name:"URL", value:"http://www.mapserver.org/development/changelog/changelog-6-2-2.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15363");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1048688");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mapserver' package(s) announced via the MGASA-2015-0097 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated mapserver packages fix security vulnerability:

SQL injection vulnerability in the msPostGISLayerSetTimeFilter function in
mappostgis.c in MapServer before 6.4.1, when a WMS-Time service is used,
allows remote attackers to execute arbitrary SQL commands via a crafted
string in a PostGIS TIME filter (CVE-2013-7262).

The mapserver package has been updated to version 6.2.2, which fixes this
issue and several other bugs, including some packaging issues which
prevented it from working anyway.");

  script_tag(name:"affected", value:"'mapserver' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"mapserver", rpm:"mapserver~6.2.2~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mapserver-perl", rpm:"mapserver-perl~6.2.2~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mapserver-php", rpm:"mapserver-php~6.2.2~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mapserver-python", rpm:"mapserver-python~6.2.2~1.2.mga4", rls:"MAGEIA4"))) {
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
