# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840501");
  script_cve_id("CVE-2010-0397", "CVE-2010-1128", "CVE-2010-1129", "CVE-2010-1130", "CVE-2010-1866", "CVE-2010-1868", "CVE-2010-1917", "CVE-2010-2094", "CVE-2010-2225", "CVE-2010-2531", "CVE-2010-2950", "CVE-2010-3065");
  script_tag(name:"creation_date", value:"2010-09-22 06:32:53 +0000 (Wed, 22 Sep 2010)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-08 18:38:19 +0000 (Thu, 08 Feb 2024)");

  script_name("Ubuntu: Security Advisory (USN-989-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|6\.06\ LTS|8\.04\ LTS|9\.04|9\.10)");

  script_xref(name:"Advisory-ID", value:"USN-989-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-989-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5' package(s) announced via the USN-989-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Auke van Slooten discovered that PHP incorrectly handled certain xmlrpc
requests. An attacker could exploit this issue to cause the PHP server to
crash, resulting in a denial of service. This issue only affected Ubuntu
6.06 LTS, 8.04 LTS, 9.04 and 9.10. (CVE-2010-0397)

It was discovered that the pseudorandom number generator in PHP did not
provide the expected entropy. An attacker could exploit this issue to
predict values that were intended to be random, such as session cookies.
This issue only affected Ubuntu 6.06 LTS, 8.04 LTS, 9.04 and 9.10.
(CVE-2010-1128)

It was discovered that PHP did not properly handle directory pathnames that
lacked a trailing slash character. An attacker could exploit this issue to
bypass safe_mode restrictions. This issue only affected Ubuntu 6.06 LTS,
8.04 LTS, 9.04 and 9.10. (CVE-2010-1129)

Grzegorz Stachowiak discovered that the PHP session extension did not
properly handle semicolon characters. An attacker could exploit this issue
to bypass safe_mode restrictions. This issue only affected Ubuntu 8.04 LTS,
9.04 and 9.10. (CVE-2010-1130)

Stefan Esser discovered that PHP incorrectly decoded remote HTTP chunked
encoding streams. An attacker could exploit this issue to cause the PHP
server to crash and possibly execute arbitrary code with application
privileges. This issue only affected Ubuntu 10.04 LTS. (CVE-2010-1866)

Mateusz Kocielski discovered that certain PHP SQLite functions incorrectly
handled empty SQL queries. An attacker could exploit this issue to possibly
execute arbitrary code with application privileges. (CVE-2010-1868)

Mateusz Kocielski discovered that PHP incorrectly handled certain arguments
to the fnmatch function. An attacker could exploit this flaw and cause the
PHP server to consume all available stack memory, resulting in a denial of
service. (CVE-2010-1917)

Stefan Esser discovered that PHP incorrectly handled certain strings in the
phar extension. An attacker could exploit this flaw to possibly view
sensitive information. This issue only affected Ubuntu 10.04 LTS.
(CVE-2010-2094, CVE-2010-2950)

Stefan Esser discovered that PHP incorrectly handled deserialization of
SPLObjectStorage objects. A remote attacker could exploit this issue to
view sensitive information and possibly execute arbitrary code with
application privileges. This issue only affected Ubuntu 8.04 LTS, 9.04,
9.10 and 10.04 LTS. (CVE-2010-2225)

It was discovered that PHP incorrectly filtered error messages when limits
for memory, execution time, or recursion were exceeded. A remote attacker
could exploit this issue to possibly view sensitive information.
(CVE-2010-2531)

Stefan Esser discovered that the PHP session serializer incorrectly handled
the PS_UNDEF_MARKER marker. An attacker could exploit this issue to alter
arbitrary session variables. (CVE-2010-3065)");

  script_tag(name:"affected", value:"'php5' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 9.04, Ubuntu 9.10, Ubuntu 10.04.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.3.2-1ubuntu4.5", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.3.2-1ubuntu4.5", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.3.2-1ubuntu4.5", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.1.2-1ubuntu3.19", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.1.2-1ubuntu3.19", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.1.2-1ubuntu3.19", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.2.4-2ubuntu5.12", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.2.4-2ubuntu5.12", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.2.4-2ubuntu5.12", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.2.6.dfsg.1-3ubuntu4.6", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.2.6.dfsg.1-3ubuntu4.6", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.2.6.dfsg.1-3ubuntu4.6", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.2.10.dfsg.1-2ubuntu6.5", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.2.10.dfsg.1-2ubuntu6.5", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.2.10.dfsg.1-2ubuntu6.5", rls:"UBUNTU9.10"))) {
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
