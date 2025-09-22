# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702934");
  script_cve_id("CVE-2014-0472", "CVE-2014-0473", "CVE-2014-0474", "CVE-2014-1418", "CVE-2014-3730");
  script_tag(name:"creation_date", value:"2014-05-18 22:00:00 +0000 (Sun, 18 May 2014)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2934-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");

  script_xref(name:"Advisory-ID", value:"DSA-2934-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-2934-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2934");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python-django' package(s) announced via the DSA-2934-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Django, a high-level Python web development framework. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2014-0472

Benjamin Bach discovered that Django incorrectly handled dotted Python paths when using the reverse() URL resolver function. An attacker able to request a specially crafted view from a Django application could use this issue to cause Django to import arbitrary modules from the Python path, resulting in possible code execution.

CVE-2014-0473

Paul McMillan discovered that Django incorrectly cached certain pages that contained CSRF cookies. A remote attacker could use this flaw to acquire the CSRF token of a different user and bypass intended CSRF protections in a Django application.

CVE-2014-0474

Michael Koziarski discovered that certain Django model field classes did not properly perform type conversion on their arguments, which allows remote attackers to obtain unexpected results.

CVE-2014-1418

Michael Nelson, Natalia Bidart and James Westby discovered that cached data in Django could be served to a different session, or to a user with no session at all. An attacker may use this to retrieve private data or poison caches.

CVE-2014-3730

Peter Kuma and Gavin Wahl discovered that Django incorrectly validated certain malformed URLs from user input. An attacker may use this to cause unexpected redirects.

For the oldstable distribution (squeeze), these problems have been fixed in version 1.2.3-3+squeeze10.

For the stable distribution (wheezy), these problems have been fixed in version 1.4.5-1+deb7u7.

For the testing distribution (jessie), these problems have been fixed in version 1.6.5-1.

For the unstable distribution (sid), these problems have been fixed in version 1.6.5-1.

We recommend that you upgrade your python-django packages.");

  script_tag(name:"affected", value:"'python-django' package(s) on Debian 6, Debian 7.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1.2.3-3+squeeze10", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-django-doc", ver:"1.2.3-3+squeeze10", rls:"DEB6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1.4.5-1+deb7u7", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-django-doc", ver:"1.4.5-1+deb7u7", rls:"DEB7"))) {
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
