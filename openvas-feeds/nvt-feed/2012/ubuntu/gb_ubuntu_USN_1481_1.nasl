# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841052");
  script_cve_id("CVE-2012-0781", "CVE-2012-1172", "CVE-2012-2143", "CVE-2012-2317", "CVE-2012-2335", "CVE-2012-2336", "CVE-2012-2386");
  script_tag(name:"creation_date", value:"2012-06-22 04:58:12 +0000 (Fri, 22 Jun 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1481-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|11\.04|11\.10|12\.04\ LTS|8\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-1481-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1481-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5' package(s) announced via the USN-1481-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that PHP incorrectly handled certain Tidy::diagnose
operations on invalid objects. A remote attacker could use this flaw to
cause PHP to crash, leading to a denial of service. (CVE-2012-0781)

It was discovered that PHP incorrectly handled certain multi-file upload
filenames. A remote attacker could use this flaw to cause a denial of
service, or to perform a directory traversal attack. (CVE-2012-1172)

Rubin Xu and Joseph Bonneau discovered that PHP incorrectly handled certain
Unicode characters in passwords passed to the crypt() function. A remote
attacker could possibly use this flaw to bypass authentication.
(CVE-2012-2143)

It was discovered that a Debian/Ubuntu specific patch caused PHP to
incorrectly handle empty salt strings. A remote attacker could possibly use
this flaw to bypass authentication. This issue only affected Ubuntu 10.04
LTS and Ubuntu 11.04. (CVE-2012-2317)

It was discovered that PHP, when used as a stand alone CGI processor
for the Apache Web Server, did not properly parse and filter query
strings. This could allow a remote attacker to execute arbitrary code
running with the privilege of the web server, or to perform a denial of
service. Configurations using mod_php5 and FastCGI were not vulnerable.
(CVE-2012-2335, CVE-2012-2336)

Alexander Gavrun discovered that the PHP Phar extension incorrectly handled
certain malformed TAR files. A remote attacker could use this flaw to
perform a denial of service, or possibly execute arbitrary code.
(CVE-2012-2386)");

  script_tag(name:"affected", value:"'php5' package(s) on Ubuntu 8.04, Ubuntu 10.04, Ubuntu 11.04, Ubuntu 11.10, Ubuntu 12.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"php5", ver:"5.3.2-1ubuntu4.17", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"php5", ver:"5.3.5-1ubuntu7.10", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.10") {

  if(!isnull(res = isdpkgvuln(pkg:"php5", ver:"5.3.6-13ubuntu3.8", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"php5", ver:"5.3.10-1ubuntu3.2", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"php5", ver:"5.2.4-2ubuntu5.25", rls:"UBUNTU8.04 LTS"))) {
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
