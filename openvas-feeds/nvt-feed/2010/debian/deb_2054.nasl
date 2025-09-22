# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67632");
  script_cve_id("CVE-2010-0097", "CVE-2010-0290", "CVE-2010-0382");
  script_tag(name:"creation_date", value:"2010-07-06 00:35:12 +0000 (Tue, 06 Jul 2010)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2054-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2054-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/DSA-2054-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2054");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bind9' package(s) announced via the DSA-2054-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several cache-poisoning vulnerabilities have been discovered in BIND. These vulnerabilities apply only if DNSSEC validation is enabled and trust anchors have been installed, which is not the default.

The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-0097

BIND does not properly validate DNSSEC NSEC records, which allows remote attackers to add the Authenticated Data (AD) flag to a forged NXDOMAIN response for an existing domain.

CVE-2010-0290

When processing crafted responses containing CNAME or DNAME records, BIND is subject to a DNS cache poisoning vulnerability, provided that DNSSEC validation is enabled and trust anchors have been installed.

CVE-2010-0382

When processing certain responses containing out-of-bailiwick data, BIND is subject to a DNS cache poisoning vulnerability, provided that DNSSEC validation is enabled and trust anchors have been installed.

In addition, this update introduce a more conservative query behavior in the presence of repeated DNSSEC validation failures, addressing the 'roll over and die' phenomenon. The new version also supports the cryptographic algorithm used by the upcoming signed ICANN DNS root (RSASHA256 from RFC 5702), and the NSEC3 secure denial of existence algorithm used by some signed top-level domains.

This update is based on a new upstream version of BIND 9, 9.6-ESV-R1. Because of the scope of changes, extra care is recommended when installing the update. Due to ABI changes, new Debian packages are included, and the update has to be installed using 'apt-get dist-upgrade' (or an equivalent aptitude command).

For the stable distribution (lenny), these problems have been fixed in version 1:9.6.ESV.R1+dfsg-0+lenny1.

For the unstable distribution (sid), these problems have been fixed in version 1:9.7.0.dfsg-1.

We recommend that you upgrade your bind9 packages.");

  script_tag(name:"affected", value:"'bind9' package(s) on Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"bind9", ver:"1:9.6.ESV.R1+dfsg-0+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bind9-doc", ver:"1:9.6.ESV.R1+dfsg-0+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bind9-host", ver:"1:9.6.ESV.R1+dfsg-0+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bind9utils", ver:"1:9.6.ESV.R1+dfsg-0+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dnsutils", ver:"1:9.6.ESV.R1+dfsg-0+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbind-dev", ver:"1:9.6.ESV.R1+dfsg-0+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbind9-50", ver:"1:9.6.ESV.R1+dfsg-0+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdns55", ver:"1:9.6.ESV.R1+dfsg-0+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisc52", ver:"1:9.6.ESV.R1+dfsg-0+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisccc50", ver:"1:9.6.ESV.R1+dfsg-0+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisccfg50", ver:"1:9.6.ESV.R1+dfsg-0+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblwres50", ver:"1:9.6.ESV.R1+dfsg-0+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lwresd", ver:"1:9.6.ESV.R1+dfsg-0+lenny1", rls:"DEB5"))) {
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
