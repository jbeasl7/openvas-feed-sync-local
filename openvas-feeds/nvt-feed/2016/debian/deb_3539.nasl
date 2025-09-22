# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703539");
  script_cve_id("CVE-2015-6360");
  script_tag(name:"creation_date", value:"2016-04-01 22:00:00 +0000 (Fri, 01 Apr 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-21 16:23:11 +0000 (Thu, 21 Apr 2016)");

  script_name("Debian: Security Advisory (DSA-3539-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3539-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3539-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3539");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'srtp' package(s) announced via the DSA-3539-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Randell Jesup and the Firefox team discovered that srtp, Cisco's reference implementation of the Secure Real-time Transport Protocol (SRTP), does not properly handle RTP header CSRC count and extension header length. A remote attacker can exploit this vulnerability to crash an application linked against libsrtp, resulting in a denial of service.

For the oldstable distribution (wheezy), this problem has been fixed in version 1.4.4+20100615~dfsg-2+deb7u2.

For the stable distribution (jessie), this problem has been fixed in version 1.4.5~20130609~dfsg-1.1+deb8u1.

We recommend that you upgrade your srtp packages.");

  script_tag(name:"affected", value:"'srtp' package(s) on Debian 7, Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libsrtp0", ver:"1.4.4+20100615~dfsg-2+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsrtp0-dev", ver:"1.4.4+20100615~dfsg-2+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"srtp-docs", ver:"1.4.4+20100615~dfsg-2+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"srtp-utils", ver:"1.4.4+20100615~dfsg-2+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"libsrtp0", ver:"1.4.5~20130609~dfsg-1.1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsrtp0-dev", ver:"1.4.5~20130609~dfsg-1.1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"srtp-docs", ver:"1.4.5~20130609~dfsg-1.1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"srtp-utils", ver:"1.4.5~20130609~dfsg-1.1+deb8u1", rls:"DEB8"))) {
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
