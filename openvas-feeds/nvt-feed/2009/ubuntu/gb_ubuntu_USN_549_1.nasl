# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840031");
  script_cve_id("CVE-2007-1285", "CVE-2007-2872", "CVE-2007-3799", "CVE-2007-3998", "CVE-2007-4657", "CVE-2007-4658", "CVE-2007-4660", "CVE-2007-4661", "CVE-2007-4662", "CVE-2007-4670", "CVE-2007-5898", "CVE-2007-5899");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 14:03:24 +0000 (Fri, 02 Feb 2024)");

  script_name("Ubuntu: Security Advisory (USN-549-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|6\.10|7\.04|7\.10)");

  script_xref(name:"Advisory-ID", value:"USN-549-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-549-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5' package(s) announced via the USN-549-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the wordwrap function did not correctly
check lengths. Remote attackers could exploit this to cause
a crash or monopolize CPU resources, resulting in a denial of
service. (CVE-2007-3998)

Integer overflows were discovered in the strspn and strcspn functions.
Attackers could exploit this to read arbitrary areas of memory, possibly
gaining access to sensitive information. (CVE-2007-4657)

Stanislav Malyshev discovered that money_format function did not correctly
handle certain tokens. If a PHP application were tricked into processing
a bad format string, a remote attacker could execute arbitrary code with
application privileges. (CVE-2007-4658)

It was discovered that the php_openssl_make_REQ function did not
correctly check buffer lengths. A remote attacker could send a
specially crafted message and execute arbitrary code with application
privileges. (CVE-2007-4662)

It was discovered that certain characters in session cookies were not
handled correctly. A remote attacker could injection values which could
lead to altered application behavior, potentially gaining additional
privileges. (CVE-2007-3799)

Gerhard Wagner discovered that the chunk_split function did not
correctly handle long strings. A remote attacker could exploit this
to execute arbitrary code with application privileges. (CVE-2007-2872,
CVE-2007-4660, CVE-2007-4661)

Stefan Esser discovered that deeply nested arrays could be made to
fill stack space. A remote attacker could exploit this to cause a
crash or monopolize CPU resources, resulting in a denial of service.
(CVE-2007-1285, CVE-2007-4670)

Rasmus Lerdorf discovered that the htmlentities and htmlspecialchars
functions did not correctly stop when handling partial multibyte
sequences. A remote attacker could exploit this to read certain areas of
memory, possibly gaining access to sensitive information. (CVE-2007-5898)

It was discovered that the output_add_rewrite_var function would
sometimes leak session id information to forms targeting remote URLs.
Malicious remote sites could use this information to gain access to a
PHP application user's login credentials. (CVE-2007-5899)");

  script_tag(name:"affected", value:"'php5' package(s) on Ubuntu 6.06, Ubuntu 6.10, Ubuntu 7.04, Ubuntu 7.10.");

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

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.1.2-1ubuntu3.10", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.1.2-1ubuntu3.10", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.1.2-1ubuntu3.10", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.1.6-1ubuntu2.7", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.1.6-1ubuntu2.7", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.1.6-1ubuntu2.7", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU7.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.2.1-0ubuntu1.5", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.2.1-0ubuntu1.5", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.2.1-0ubuntu1.5", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU7.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.2.3-1ubuntu6.1", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.2.3-1ubuntu6.1", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.2.3-1ubuntu6.1", rls:"UBUNTU7.10"))) {
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
