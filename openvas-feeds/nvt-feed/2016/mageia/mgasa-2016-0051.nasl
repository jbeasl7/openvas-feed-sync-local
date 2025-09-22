# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131209");
  script_cve_id("CVE-2016-1927", "CVE-2016-2038", "CVE-2016-2039", "CVE-2016-2040", "CVE-2016-2041");
  script_tag(name:"creation_date", value:"2016-02-08 17:55:16 +0000 (Mon, 08 Feb 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-02-23 16:18:39 +0000 (Tue, 23 Feb 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0051)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0051");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0051.html");
  script_xref(name:"URL", value:"http://lwn.net/Vulnerabilities/674259/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17633");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/files/4.4.15.3/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/news/2016/1/28/phpmyadmin-454-44153-and-401013-are-released/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/news/2016/1/29/phpmyadmin-401014-44154-and-451/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-1/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-2/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-3/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-4/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-5/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'phpmyadmin, phpseclib' package(s) announced via the MGASA-2016-0051 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Password suggestion functionality uses Math.random() which does not
provide cryptographically secure random numbers (CVE-2016-1927).

By calling some scripts that are part of phpMyAdmin in an unexpected way,
it is possible to trigger phpMyAdmin to display a PHP error message which
contains the full path of the directory where phpMyAdmin is installed
(CVE-2016-2038).

The XSRF/CSRF token is generated with a weak algorithm using functions
that do not return cryptographically secure values (CVE-2016-2039).

With a crafted table name it is possible to trigger an XSS attack in the
database search page. With a crafted SET value or a crafted search query,
it is possible to trigger an XSS attacks in the zoom search page. With a
crafted hostname header, it is possible to trigger an XSS attacks in the
home page (CVE-2016-2040).

The comparison of the XSRF/CSRF token parameter with the value saved in
the session is vulnerable to timing attacks. Moreover, the comparison
could be bypassed if the XSRF/CSRF token matches a particular pattern
(CVE-2016-2041).

The phpmyadmin package has been updated to version 4.4.15.4 in the 4.4.x
stable branch, and the phpseclib dependency has been updated to version
2.0.1.");

  script_tag(name:"affected", value:"'phpmyadmin, phpseclib' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"phpmyadmin", rpm:"phpmyadmin~4.4.15.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"phpseclib", rpm:"phpseclib~2.0.1~1.mga5", rls:"MAGEIA5"))) {
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
