# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55261");
  script_cve_id("CVE-2005-1268", "CVE-2005-2088", "CVE-2005-2700", "CVE-2005-2728");
  script_tag(name:"creation_date", value:"2008-01-17 22:03:37 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-805-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-805-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/DSA-805-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-805");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'apache2' package(s) announced via the DSA-805-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several problems have been discovered in Apache2, the next generation, scalable, extendable web server. The Common Vulnerabilities and Exposures project identifies the following problems:

CAN-2005-1268

Marc Stern discovered an off-by-one error in the mod_ssl Certificate Revocation List (CRL) verification callback. When Apache is configured to use a CRL this can be used to cause a denial of service.

CAN-2005-2088

A vulnerability has been discovered in the Apache web server. When it is acting as an HTTP proxy, it allows remote attackers to poison the web cache, bypass web application firewall protection, and conduct cross-site scripting attacks, which causes Apache to incorrectly handle and forward the body of the request.

CAN-2005-2700

A problem has been discovered in mod_ssl, which provides strong cryptography (HTTPS support) for Apache that allows remote attackers to bypass access restrictions.

CAN-2005-2728

The byte-range filter in Apache 2.0 allows remote attackers to cause a denial of service via an HTTP header with a large Range field.

The old stable distribution (woody) does not contain Apache2 packages.

For the stable distribution (sarge) these problems have been fixed in version 2.0.54-5.

For the unstable distribution (sid) these problems have been fixed in version 2.0.54-5.

We recommend that you upgrade your apache2 packages.");

  script_tag(name:"affected", value:"'apache2' package(s) on Debian 3.1.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.0.54-5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-common", ver:"2.0.54-5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-doc", ver:"2.0.54-5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-perchild", ver:"2.0.54-5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.0.54-5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-threadpool", ver:"2.0.54-5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.0.54-5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-prefork-dev", ver:"2.0.54-5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-threaded-dev", ver:"2.0.54-5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-utils", ver:"2.0.54-5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapr0", ver:"2.0.54-5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapr0-dev", ver:"2.0.54-5", rls:"DEB3.1"))) {
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
