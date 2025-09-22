# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0285");
  script_cve_id("CVE-2013-4338", "CVE-2013-4339", "CVE-2013-4340", "CVE-2013-5738", "CVE-2013-5739");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2013-0285)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(2|3)");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0285");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0285.html");
  script_xref(name:"URL", value:"http://wordpress.org/news/2013/09/wordpress-3-6-1/");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2757");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11218");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-phpmailer, wordpress' package(s) announced via the MGASA-2013-0285 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"wp-includes/functions.php in WordPress before 3.6.1 does not properly
determine whether data has been serialized, which allows remote
attackers to execute arbitrary code by triggering erroneous PHP
unserialize operations (CVE-2013-4338).

WordPress before 3.6.1 does not properly validate URLs before use in
an HTTP redirect, which allows remote attackers to bypass intended
redirection restrictions via a crafted string (CVE-2013-4339).

wp-admin/includes/post.php in WordPress before 3.6.1 allows remote
authenticated users to spoof the authorship of a post by leveraging
the Author role and providing a modified user_ID parameter
(CVE-2013-4340).

The get_allowed_mime_types function in wp-includes/functions.php in
WordPress before 3.6.1 does not require the unfiltered_html capability
for uploads of .htm and .html files, which might make it easier for
remote authenticated users to conduct cross-site scripting (XSS)
attacks via a crafted file (CVE-2013-5738).

The default configuration of WordPress before 3.6.1 does not prevent
uploads of .swf and .exe files, which might make it easier for remote
authenticated users to conduct cross-site scripting (XSS) attacks via
a crafted file, related to the get_allowed_mime_types function in
wp-includes/functions.php (CVE-2013-5739).

Additionally, php-phpmailer has been updated to a newer version required
by the updated wordpress.");

  script_tag(name:"affected", value:"'php-phpmailer, wordpress' package(s) on Mageia 2, Mageia 3.");

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

if(release == "MAGEIA2") {

  if(!isnull(res = isrpmvuln(pkg:"php-phpmailer", rpm:"php-phpmailer~5.2.7~0.20130917.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wordpress", rpm:"wordpress~3.6.1~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"php-phpmailer", rpm:"php-phpmailer~5.2.7~0.20130917.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wordpress", rpm:"wordpress~3.6.1~1.mga3", rls:"MAGEIA3"))) {
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
