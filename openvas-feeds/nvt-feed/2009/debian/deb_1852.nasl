# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64631");
  script_cve_id("CVE-2009-2666");
  script_tag(name:"creation_date", value:"2009-08-17 14:54:45 +0000 (Mon, 17 Aug 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1852-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1852-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1852-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1852");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'fetchmail' package(s) announced via the DSA-1852-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that fetchmail, a full-featured remote mail retrieval and forwarding utility, is vulnerable to the 'Null Prefix Attacks Against SSL/TLS Certificates' recently published at the Blackhat conference. This allows an attacker to perform undetected man-in-the-middle attacks via a crafted ITU-T X.509 certificate with an injected null byte in the subjectAltName or Common Name fields.

Note, as a fetchmail user you should always use strict certificate validation through either these option combinations: sslcertck ssl sslproto ssl3 (for service on SSL-wrapped ports) or sslcertck sslproto tls1 (for STARTTLS-based services)

For the oldstable distribution (etch), this problem has been fixed in version 6.3.6-1etch2.

For the stable distribution (lenny), this problem has been fixed in version 6.3.9~rc2-4+lenny1.

For the testing distribution (squeeze), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 6.3.9~rc2-6.

We recommend that you upgrade your fetchmail packages.");

  script_tag(name:"affected", value:"'fetchmail' package(s) on Debian 4, Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"fetchmail", ver:"6.3.6-1etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fetchmailconf", ver:"6.3.6-1etch2", rls:"DEB4"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"fetchmail", ver:"6.3.9~rc2-4+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fetchmailconf", ver:"6.3.9~rc2-4+lenny1", rls:"DEB5"))) {
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
