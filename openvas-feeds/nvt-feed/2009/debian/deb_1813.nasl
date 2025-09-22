# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64186");
  script_cve_id("CVE-2009-0547", "CVE-2009-0582", "CVE-2009-0587");
  script_tag(name:"creation_date", value:"2009-06-09 17:38:29 +0000 (Tue, 09 Jun 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1813-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1813-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1813-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1813");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'evolution-data-server' package(s) announced via the DSA-1813-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in evolution-data-server, the database backend server for the evolution groupware suite. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-0587

It was discovered that evolution-data-server is prone to integer overflows triggered by large base64 strings.

CVE-2009-0547

Joachim Breitner discovered that S/MIME signatures are not verified properly, which can lead to spoofing attacks.

CVE-2009-0582

It was discovered that NTLM authentication challenge packets are not validated properly when using the NTLM authentication method, which could lead to an information disclosure or a denial of service.

For the oldstable distribution (etch), these problems have been fixed in version 1.6.3-5etch2.

For the stable distribution (lenny), these problems have been fixed in version 2.22.3-1.1+lenny1.

For the testing distribution (squeeze) and the unstable distribution (sid), these problems have been fixed in version 2.26.1.1-1.

We recommend that you upgrade your evolution-data-server packages.");

  script_tag(name:"affected", value:"'evolution-data-server' package(s) on Debian 4, Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"evolution-data-server", ver:"1.6.3-5etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"evolution-data-server-common", ver:"1.6.3-5etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"evolution-data-server-dbg", ver:"1.6.3-5etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"evolution-data-server-dev", ver:"1.6.3-5etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcamel1.2-8", ver:"1.6.3-5etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcamel1.2-dev", ver:"1.6.3-5etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libebook1.2-5", ver:"1.6.3-5etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libebook1.2-dev", ver:"1.6.3-5etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libecal1.2-6", ver:"1.6.3-5etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libecal1.2-dev", ver:"1.6.3-5etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libedata-book1.2-2", ver:"1.6.3-5etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libedata-book1.2-dev", ver:"1.6.3-5etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libedata-cal1.2-5", ver:"1.6.3-5etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libedata-cal1.2-dev", ver:"1.6.3-5etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libedataserver1.2-7", ver:"1.6.3-5etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libedataserver1.2-dev", ver:"1.6.3-5etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libedataserverui1.2-6", ver:"1.6.3-5etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libedataserverui1.2-dev", ver:"1.6.3-5etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libegroupwise1.2-10", ver:"1.6.3-5etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libegroupwise1.2-dev", ver:"1.6.3-5etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexchange-storage1.2-1", ver:"1.6.3-5etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexchange-storage1.2-dev", ver:"1.6.3-5etch2", rls:"DEB4"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"evolution-data-server", ver:"2.22.3-1.1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"evolution-data-server-common", ver:"2.22.3-1.1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"evolution-data-server-dbg", ver:"2.22.3-1.1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"evolution-data-server-dev", ver:"2.22.3-1.1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcamel1.2-11", ver:"2.22.3-1.1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcamel1.2-dev", ver:"2.22.3-1.1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libebook1.2-9", ver:"2.22.3-1.1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libebook1.2-dev", ver:"2.22.3-1.1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libecal1.2-7", ver:"2.22.3-1.1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libecal1.2-dev", ver:"2.22.3-1.1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libedata-book1.2-2", ver:"2.22.3-1.1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libedata-book1.2-dev", ver:"2.22.3-1.1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libedata-cal1.2-6", ver:"2.22.3-1.1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libedata-cal1.2-dev", ver:"2.22.3-1.1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libedataserver1.2-9", ver:"2.22.3-1.1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libedataserver1.2-dev", ver:"2.22.3-1.1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libedataserverui1.2-8", ver:"2.22.3-1.1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libedataserverui1.2-dev", ver:"2.22.3-1.1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libegroupwise1.2-13", ver:"2.22.3-1.1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libegroupwise1.2-dev", ver:"2.22.3-1.1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexchange-storage1.2-3", ver:"2.22.3-1.1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexchange-storage1.2-dev", ver:"2.22.3-1.1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgdata-google1.2-1", ver:"2.22.3-1.1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgdata-google1.2-dev", ver:"2.22.3-1.1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgdata1.2-1", ver:"2.22.3-1.1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgdata1.2-dev", ver:"2.22.3-1.1+lenny1", rls:"DEB5"))) {
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
