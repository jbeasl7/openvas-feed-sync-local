# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71261");
  script_cve_id("CVE-2006-7250", "CVE-2012-0884", "CVE-2012-1165", "CVE-2012-2110", "CVE-2012-2131");
  script_tag(name:"creation_date", value:"2012-04-30 11:57:59 +0000 (Mon, 30 Apr 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2454-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2454-2");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/DSA-2454-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2454");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssl' package(s) announced via the DSA-2454-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in OpenSSL. The Common Vulnerabilities and Exposures project identifies the following issues:

CVE-2012-0884

Ivan Nestlerode discovered a weakness in the CMS and PKCS #7 implementations that could allow an attacker to decrypt data via a Million Message Attack (MMA).

CVE-2012-1165

It was discovered that a NULL pointer could be dereferenced when parsing certain S/MIME messages, leading to denial of service.

CVE-2012-2110

Tavis Ormandy, Google Security Team, discovered a vulnerability in the way DER-encoded ASN.1 data is parsed that can result in a heap overflow.

Additionally, the fix for CVE-2011-4619 has been updated to address an issue with SGC handshakes.

Tomas Hoger, Red Hat, discovered that the fix for CVE-2012-2110 for the 0.9.8 series of OpenSSL was incomplete. It has been assigned the CVE-2012-2131 identifier.

For the stable distribution (squeeze), these problems have been fixed in version 0.9.8o-4squeeze12.

For the testing distribution (wheezy), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 1.0.1a-1.

We recommend that you upgrade your openssl packages.");

  script_tag(name:"affected", value:"'openssl' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libcrypto0.9.8-udeb", ver:"0.9.8o-4squeeze12", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl-dev", ver:"0.9.8o-4squeeze12", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8o-4squeeze12", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl0.9.8-dbg", ver:"0.9.8o-4squeeze12", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"0.9.8o-4squeeze12", rls:"DEB6"))) {
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
