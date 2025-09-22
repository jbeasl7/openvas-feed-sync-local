# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2010.1977");
  script_cve_id("CVE-2008-2316", "CVE-2009-3560", "CVE-2009-3720");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-02-01T14:37:13+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:13 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1977-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1977-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/DSA-1977-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1977");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python2.4, python2.5' package(s) announced via the DSA-1977-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jukka Taimisto, Tero Rontti and Rauli Kaksonen discovered that the embedded Expat copy in the interpreter for the Python language, does not properly process malformed or crafted XML files. (CVE-2009-3560 CVE-2009-3720) This vulnerability could allow an attacker to cause a denial of service while parsing a malformed XML file.

In addition, this update fixes an integer overflow in the hashlib module in python2.5. This vulnerability could allow an attacker to defeat cryptographic digests. (CVE-2008-2316) It only affects the oldstable distribution (etch).

For the oldstable distribution (etch), these problems have been fixed in version 2.4.4-3+etch3 for python2.4 and version 2.5-5+etch2 for python2.5.

For the stable distribution (lenny), these problems have been fixed in version 2.4.6-1+lenny1 for python2.4 and version 2.5.2-15+lenny1 for python2.5.

For the unstable distribution (sid), these problems have been fixed in version 2.5.4-3.1 for python2.5, and will migrate to the testing distribution (squeeze) shortly. python2.4 has been removed from the testing distribution (squeeze), and it will be removed from the unstable distribution soon.

We recommend that you upgrade your python packages.");

  script_tag(name:"affected", value:"'python2.4, python2.5' package(s) on Debian 4, Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"idle-python2.4", ver:"2.4.4-3+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"idle-python2.5", ver:"2.5-5+etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.4", ver:"2.4.4-3+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.4-dbg", ver:"2.4.4-3+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.4-dev", ver:"2.4.4-3+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.4-examples", ver:"2.4.4-3+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.4-minimal", ver:"2.4.4-3+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.5", ver:"2.5-5+etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.5-dbg", ver:"2.5-5+etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.5-dev", ver:"2.5-5+etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.5-examples", ver:"2.5-5+etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.5-minimal", ver:"2.5-5+etch2", rls:"DEB4"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"idle-python2.4", ver:"2.4.6-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"idle-python2.5", ver:"2.5.2-15+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.4", ver:"2.4.6-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.4-dbg", ver:"2.4.6-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.4-dev", ver:"2.4.6-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.4-examples", ver:"2.4.6-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.4-minimal", ver:"2.4.6-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.5", ver:"2.5.2-15+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.5-dbg", ver:"2.5.2-15+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.5-dev", ver:"2.5.2-15+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.5-examples", ver:"2.5.2-15+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.5-minimal", ver:"2.5.2-15+lenny1", rls:"DEB5"))) {
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
