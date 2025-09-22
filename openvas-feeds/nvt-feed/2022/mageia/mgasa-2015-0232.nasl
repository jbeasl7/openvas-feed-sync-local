# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0232");
  script_cve_id("CVE-2015-3902", "CVE-2015-3903");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0232)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0232");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0232.html");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2015-2.php");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2015-3.php");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15945");
  script_xref(name:"URL", value:"https://sourceforge.net/p/phpmyadmin/news/2014/05/phpmyadmin-420-is-released/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'phpmyadmin' package(s) announced via the MGASA-2015-0232 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated phpmyadmin package fixes security vulnerabilities:

In phpMyAdmin before 4.2.13.3, by deceiving a user to click on a crafted URL,
it is possible to alter the configuration file being generated with phpMyAdmin
setup (CVE-2015-3902).

In phpMyAdmin before 4.2.13.3, a vulnerability in the API call to GitHub can
be exploited to perform a man-in-the-middle attack (CVE-2015-3903).

With this update, the phpmyadmin package has been updated to the 4.2 branch,
which has some additional changes and new features. The 4.1 branch is no
longer supported.");

  script_tag(name:"affected", value:"'phpmyadmin' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"phpmyadmin", rpm:"phpmyadmin~4.2.13.3~1.mga4", rls:"MAGEIA4"))) {
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
