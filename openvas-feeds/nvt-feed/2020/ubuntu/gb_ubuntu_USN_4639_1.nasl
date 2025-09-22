# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844721");
  script_cve_id("CVE-2018-19968", "CVE-2018-19970", "CVE-2018-7260", "CVE-2019-11768", "CVE-2019-12616", "CVE-2019-19617", "CVE-2019-6798", "CVE-2019-6799", "CVE-2020-10802", "CVE-2020-10803", "CVE-2020-10804", "CVE-2020-26934", "CVE-2020-26935", "CVE-2020-5504");
  script_tag(name:"creation_date", value:"2020-11-20 04:00:43 +0000 (Fri, 20 Nov 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-26 16:50:35 +0000 (Mon, 26 Oct 2020)");

  script_name("Ubuntu: Security Advisory (USN-4639-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-4639-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4639-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'phpmyadmin' package(s) announced via the USN-4639-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was a bug in the way phpMyAdmin handles the
phpMyAdmin Configuration Storage tables. An authenticated attacker could
use this vulnerability to cause phpmyAdmin to leak sensitive files.
(CVE-2018-19968)

It was discovered that phpMyAdmin incorrectly handled user input. An
attacker could possibly use this for an XSS attack. (CVE-2018-19970)

It was discovered that phpMyAdmin mishandled certain input. An attacker
could use this vulnerability to execute a cross-site scripting (XSS) attack
via a crafted URL. (CVE-2018-7260)

It was discovered that phpMyAdmin failed to sanitize certain input. An
attacker could use this vulnerability to execute an SQL injection attack
via a specially crafted database name. (CVE-2019-11768)

It was discovered that phpmyadmin incorrectly handled some requests. An
attacker could possibly use this to perform a CSRF attack. (CVE-2019-12616)

It was discovered that phpMyAdmin failed to sanitize certain input. An
attacker could use this vulnerability to execute an SQL injection attack
via a specially crafted username. (CVE-2019-6798, CVE-2020-10804,
CVE-2020-5504)

It was discovered that phpMyAdmin would allow sensitive files to be leaked
if certain configuration options were set. An attacker could use this
vulnerability to access confidential information. (CVE-2019-6799)

It was discovered that phpMyAdmin failed to sanitize certain input. An
attacker could use this vulnerability to execute an SQL injection attack
via a specially crafted database or table name. (CVE-2020-10802)

It was discovered that phpMyAdmin did not properly handle data from the
database when displaying it. If an attacker were to insert specially-
crafted data into certain database tables, the attacker could execute a
cross-site scripting (XSS) attack. (CVE-2020-10803)

It was discovered that phpMyAdmin was vulnerable to an XSS attack. If a
victim were to click on a crafted link, an attacker could run malicious
JavaScript on the victim's system. (CVE-2020-26934)

It was discovered that phpMyAdmin did not properly handler certain SQL
statements in the search feature. An attacker could use this vulnerability
to inject malicious SQL into a query. (CVE-2020-26935)

It was discovered that phpMyAdmin did not properly sanitize certain input.
An attacker could use this vulnerability to possibly execute an HTML injection
or a cross-site scripting (XSS) attack. (CVE-2019-19617)");

  script_tag(name:"affected", value:"'phpmyadmin' package(s) on Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"phpmyadmin", ver:"4:4.6.6-5ubuntu0.5", rls:"UBUNTU18.04 LTS"))) {
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
