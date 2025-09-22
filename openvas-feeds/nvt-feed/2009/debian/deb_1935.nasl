# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66295");
  script_cve_id("CVE-2009-2409", "CVE-2009-2730");
  script_tag(name:"creation_date", value:"2009-11-23 19:51:51 +0000 (Mon, 23 Nov 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1935-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1935-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1935-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1935");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gnutls13, gnutls26' package(s) announced via the DSA-1935-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dan Kaminsky and Moxie Marlinspike discovered that gnutls, an implementation of the TLS/SSL protocol, does not properly handle a '0' character in a domain name in the subject's Common Name or Subject Alternative Name (SAN) field of an X.509 certificate, which allows man-in-the-middle attackers to spoof arbitrary SSL servers via a crafted certificate issued by a legitimate Certification Authority. (CVE-2009-2730)

In addition, with this update, certificates with MD2 hash signatures are no longer accepted since they're no longer considered cryptograhically secure. It only affects the oldstable distribution (etch).(CVE-2009-2409)

For the oldstable distribution (etch), these problems have been fixed in version 1.4.4-3+etch5 for gnutls13.

For the stable distribution (lenny), these problems have been fixed in version 2.4.2-6+lenny2 for gnutls26.

For the testing distribution (squeeze), and the unstable distribution (sid), these problems have been fixed in version 2.8.3-1 for gnutls26.

We recommend that you upgrade your gnutls13/gnutls26 packages.");

  script_tag(name:"affected", value:"'gnutls13, gnutls26' package(s) on Debian 4, Debian 5.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"gnutls-bin", ver:"1.4.4-3+etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnutls-doc", ver:"1.4.4-3+etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls-dev", ver:"1.4.4-3+etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls13", ver:"1.4.4-3+etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls13-dbg", ver:"1.4.4-3+etch5", rls:"DEB4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"gnutls-bin", ver:"2.4.2-6+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnutls-doc", ver:"2.4.2-6+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"guile-gnutls", ver:"2.4.2-6+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls-dev", ver:"2.4.2-6+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls26", ver:"2.4.2-6+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls26-dbg", ver:"2.4.2-6+lenny2", rls:"DEB5"))) {
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
