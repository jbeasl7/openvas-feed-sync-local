# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891560");
  script_cve_id("CVE-2018-10844", "CVE-2018-10845", "CVE-2018-10846");
  script_tag(name:"creation_date", value:"2018-11-04 23:00:00 +0000 (Sun, 04 Nov 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-01 13:44:59 +0000 (Thu, 01 Nov 2018)");

  script_name("Debian: Security Advisory (DLA-1560-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1560-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/DLA-1560-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gnutls28' package(s) announced via the DLA-1560-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A set of vulnerabilities was discovered in GnuTLS which allowed attackers to do plain text recovery on TLS connections with certain cipher types.

CVE-2018-10844

It was found that the GnuTLS implementation of HMAC-SHA-256 was vulnerable to a Lucky thirteen style attack. Remote attackers could use this flaw to conduct distinguishing attacks and plaintext-recovery attacks via statistical analysis of timing data using crafted packets.

CVE-2018-10845

It was found that the GnuTLS implementation of HMAC-SHA-384 was vulnerable to a Lucky thirteen style attack. Remote attackers could use this flaw to conduct distinguishing attacks and plain text recovery attacks via statistical analysis of timing data using crafted packets.

CVE-2018-10846

A cache-based side channel in GnuTLS implementation that leads to plain text recovery in cross-VM attack setting was found. An attacker could use a combination of Just in Time Prime+probe attack in combination with Lucky-13 attack to recover plain text using crafted packets.

For Debian 8 Jessie, these problems have been fixed in version 3.3.30-0+deb8u1. It was found to be more practical to update to the latest upstream version of the 3.3.x branch since upstream's fixes were rather invasive and required cipher list changes anyways. This will facilitate future LTS updates as well.

This change therefore also includes the following major policy changes, as documented in the NEWS file:

ARCFOUR (RC4) and SSL 3.0 are no longer included in the default priorities list. Those have to be explicitly enabled, e.g., with a string like 'NORMAL:+ARCFOUR-128' or 'NORMAL:+VERS-SSL3.0', respectively.

The ciphers utilizing HMAC-SHA384 and SHA256 have been removed from the default priority strings. They are not necessary for compatibility or other purpose and provide no advantage over their SHA1 counter-parts, as they all depend on the legacy TLS CBC block mode.

Follow closely RFC5280 recommendations and use UTCTime for dates prior to 2050.

Require strict DER encoding for certificates, OCSP requests, private keys, CRLs and certificate requests, in order to reduce issues due to the complexity of BER rules.

Refuse to import v1 or v2 certificates that contain extensions.

API and ABI compatibility is retained, however, although new symbols have been added. Many bugfixes are also included in the upload. See the provided upstream changelog for more details.

We recommend that you upgrade your gnutls28 packages and do not expect significant breakage.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'gnutls28' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"gnutls-bin", ver:"3.3.30-0+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnutls-doc", ver:"3.3.30-0+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"guile-gnutls", ver:"3.3.30-0+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls-deb0-28", ver:"3.3.30-0+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls-openssl27", ver:"3.3.30-0+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls28-dbg", ver:"3.3.30-0+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls28-dev", ver:"3.3.30-0+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgnutlsxx28", ver:"3.3.30-0+deb8u1", rls:"DEB8"))) {
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
