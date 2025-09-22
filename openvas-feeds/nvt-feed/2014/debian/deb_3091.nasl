# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703091");
  script_cve_id("CVE-2014-7273", "CVE-2014-7274", "CVE-2014-7275");
  script_tag(name:"creation_date", value:"2014-12-06 23:00:00 +0000 (Sat, 06 Dec 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3091-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3091-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-3091-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3091");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'getmail4' package(s) announced via the DSA-3091-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in getmail4, a mail retriever with support for POP3, IMAP4 and SDPS, that could allow man-in-the-middle attacks.

CVE-2014-7273

The IMAP-over-SSL implementation in getmail 4.0.0 through 4.43.0 does not verify X.509 certificates from SSL servers, which allows man-in-the-middle attackers to spoof IMAP servers and obtain sensitive information via a crafted certificate.

CVE-2014-7274

The IMAP-over-SSL implementation in getmail 4.44.0 does not verify that the server hostname matches a domain name in the subject's Common Name (CN) field of the X.509 certificate, which allows man-in-the-middle attackers to spoof IMAP servers and obtain sensitive information via a crafted certificate from a recognized Certification Authority.

CVE-2014-7275

The POP3-over-SSL implementation in getmail 4.0.0 through 4.44.0 does not verify X.509 certificates from SSL servers, which allows man-in-the-middle attackers to spoof POP3 servers and obtain sensitive information via a crafted certificate.

For the stable distribution (wheezy), these problems have been fixed in version 4.46.0-1~deb7u1.

For the upcoming stable distribution (jessie), these problems have been fixed in version 4.46.0-1.

For the unstable distribution (sid), these problems have been fixed in version 4.46.0-1.

We recommend that you upgrade your getmail4 packages.");

  script_tag(name:"affected", value:"'getmail4' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"getmail4", ver:"4.46.0-1~deb7u1", rls:"DEB7"))) {
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
