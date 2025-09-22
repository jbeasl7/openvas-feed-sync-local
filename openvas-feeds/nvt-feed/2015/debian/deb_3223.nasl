# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703223");
  script_cve_id("CVE-2015-1798", "CVE-2015-1799", "CVE-2015-3405");
  script_tag(name:"creation_date", value:"2015-04-11 22:00:00 +0000 (Sat, 11 Apr 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-25 14:55:58 +0000 (Fri, 25 Aug 2017)");

  script_name("Debian: Security Advisory (DSA-3223-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3223-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3223-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3223");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ntp' package(s) announced via the DSA-3223-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in ntp, an implementation of the Network Time Protocol:

CVE-2015-1798

When configured to use a symmetric key with an NTP peer, ntpd would accept packets without MAC as if they had a valid MAC. This could allow a remote attacker to bypass the packet authentication and send malicious packets without having to know the symmetric key.

CVE-2015-1799

When peering with other NTP hosts using authenticated symmetric association, ntpd would update its internal state variables before the MAC of the NTP messages was validated. This could allow a remote attacker to cause a denial of service by impeding synchronization between NTP peers.

Additionally, it was discovered that generating MD5 keys using ntp-keygen on big endian machines would either trigger an endless loop, or generate non-random keys.

For the stable distribution (wheezy), these problems have been fixed in version 1:4.2.6.p5+dfsg-2+deb7u4.

For the unstable distribution (sid), these problems have been fixed in version 1:4.2.6.p5+dfsg-7.

We recommend that you upgrade your ntp packages.");

  script_tag(name:"affected", value:"'ntp' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ntp", ver:"1:4.2.6.p5+dfsg-2+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntp-doc", ver:"1:4.2.6.p5+dfsg-2+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntpdate", ver:"1:4.2.6.p5+dfsg-2+deb7u4", rls:"DEB7"))) {
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
