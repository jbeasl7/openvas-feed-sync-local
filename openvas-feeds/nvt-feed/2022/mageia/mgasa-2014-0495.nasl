# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0495");
  script_cve_id("CVE-2014-8958", "CVE-2014-8959", "CVE-2014-8960", "CVE-2014-8961");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0495)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0495");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0495.html");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-13.php");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-14.php");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-15.php");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-16.php");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14637");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'phpmyadmin' package(s) announced via the MGASA-2014-0495 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated phpmyadmin package fixes security vulnerabilities:

In phpMyAdmin before 4.1.14.7, with a crafted database, table or column name
it is possible to trigger an XSS attack in the table browse page, with a
crafted ENUM value it is possible to trigger XSS attacks in the table print
view and zoom search pages, and with a crafted value for font size it is
possible to trigger an XSS attack in the home page (CVE-2014-8958).

In phpMyAdmin before 4.1.14.7, in the GIS editor feature, a parameter
specifying the geometry type was not correctly validated, opening the door to
a local file inclusion attack (CVE-2014-8959).

In phpMyAdmin before 4.1.14.7, with a crafted file name it is possible to
trigger an XSS in the error reporting page (CVE-2014-8960).

In phpMyAdmin before 4.1.14.7, in the error reporting feature, a parameter
specifying the file was not correctly validated, allowing the attacker to
derive the line count of an arbitrary file (CVE-2014-8961).");

  script_tag(name:"affected", value:"'phpmyadmin' package(s) on Mageia 3, Mageia 4.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"phpmyadmin", rpm:"phpmyadmin~4.1.14.7~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"phpmyadmin", rpm:"phpmyadmin~4.1.14.7~1.mga4", rls:"MAGEIA4"))) {
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
