# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2011.2141");
  script_cve_id("CVE-2009-3555", "CVE-2010-4180");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-02-01T14:37:13+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:13 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2141-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2141-2");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2141-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2141");
  script_xref(name:"URL", value:"https://www.debian.org/security/");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nss' package(s) announced via the DSA-2141-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"DSA-2141 consists of three individual parts, which can be viewed in the mailing list archive: DSA 2141-1 (openssl), DSA 2141-2 (nss), DSA 2141-3 (apache2), and DSA 2141-4 (lighttpd). This page only covers the first part, openssl.

CVE-2009-3555

Marsh Ray, Steve Dispensa, and Martin Rex discovered a flaw in the TLS and SSLv3 protocols. If an attacker could perform a man in the middle attack at the start of a TLS connection, the attacker could inject arbitrary content at the beginning of the user's session. This update adds backported support for the new RFC5746 renegotiation extension which fixes this issue.

If openssl is used in a server application, it will by default no longer accept renegotiation from clients that do not support the RFC5746 secure renegotiation extension. A separate advisory will add RFC5746 support for nss, the security library used by the iceweasel web browser. For apache2, there will be an update which allows to re-enable insecure renegotiation.

This version of openssl is not compatible with older versions of tor. You have to use at least tor version 0.2.1.26-1~lenny+1, which has been included in the point release 5.0.7 of Debian stable.

Currently we are not aware of other software with similar compatibility problems.

CVE-2010-4180

In addition, this update fixes a flaw that allowed a client to bypass restrictions configured in the server for the used cipher suite.

For the stable distribution (lenny), this problem has been fixed in version 0.9.8g-15+lenny11.

For the unstable distribution (sid), and the testing distribution (squeeze), this problem has been fixed in version 0.9.8o-4.

We recommend that you upgrade your openssl package.

Further information about Debian Security Advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'nss' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-1d", ver:"3.12.3.1-0lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-1d-dbg", ver:"3.12.3.1-0lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-dev", ver:"3.12.3.1-0lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-tools", ver:"3.12.3.1-0lenny3", rls:"DEB5"))) {
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
