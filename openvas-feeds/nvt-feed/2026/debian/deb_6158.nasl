# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2026.6158");
  script_cve_id("CVE-2026-24481", "CVE-2026-24484", "CVE-2026-24485", "CVE-2026-25576", "CVE-2026-25637", "CVE-2026-25638", "CVE-2026-25794", "CVE-2026-25795", "CVE-2026-25796", "CVE-2026-25797", "CVE-2026-25798", "CVE-2026-25799", "CVE-2026-25897", "CVE-2026-25898", "CVE-2026-25965", "CVE-2026-25966", "CVE-2026-25967", "CVE-2026-25968", "CVE-2026-25969", "CVE-2026-25970", "CVE-2026-25971", "CVE-2026-25982", "CVE-2026-25983", "CVE-2026-25985", "CVE-2026-25986", "CVE-2026-25987", "CVE-2026-25988", "CVE-2026-25989", "CVE-2026-26066", "CVE-2026-26283", "CVE-2026-26284", "CVE-2026-26983", "CVE-2026-27798", "CVE-2026-27799");
  script_tag(name:"creation_date", value:"2026-03-10 06:49:44 +0000 (Tue, 10 Mar 2026)");
  script_version("2026-03-10T10:15:11+0000");
  script_tag(name:"last_modification", value:"2026-03-10 10:15:11 +0000 (Tue, 10 Mar 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-25 15:53:11 +0000 (Wed, 25 Feb 2026)");

  script_name("Debian: Security Advisory (DSA-6158-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB13");

  script_xref(name:"Advisory-ID", value:"DSA-6158-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2026/DSA-6158-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'imagemagick' package(s) announced via the DSA-6158-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Debian 13.");

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

if(release == "DEB13") {

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick", ver:"8:7.1.1.43+dfsg1-1+deb13u6", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-7-common", ver:"8:7.1.1.43+dfsg1-1+deb13u6", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-7-doc", ver:"8:7.1.1.43+dfsg1-1+deb13u6", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-7.q16", ver:"8:7.1.1.43+dfsg1-1+deb13u6", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-7.q16hdri", ver:"8:7.1.1.43+dfsg1-1+deb13u6", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-perl", ver:"8:7.1.1.43+dfsg1-1+deb13u6", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-q16-perl", ver:"8:7.1.1.43+dfsg1-1+deb13u6", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-q16hdri-perl", ver:"8:7.1.1.43+dfsg1-1+deb13u6", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-7-headers", ver:"8:7.1.1.43+dfsg1-1+deb13u6", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-7.q16-5", ver:"8:7.1.1.43+dfsg1-1+deb13u6", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-7.q16-dev", ver:"8:7.1.1.43+dfsg1-1+deb13u6", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-7.q16hdri-5", ver:"8:7.1.1.43+dfsg1-1+deb13u6", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-7.q16hdri-dev", ver:"8:7.1.1.43+dfsg1-1+deb13u6", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-dev", ver:"8:7.1.1.43+dfsg1-1+deb13u6", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-7-arch-config", ver:"8:7.1.1.43+dfsg1-1+deb13u6", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-7-headers", ver:"8:7.1.1.43+dfsg1-1+deb13u6", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-7.q16-10", ver:"8:7.1.1.43+dfsg1-1+deb13u6", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-7.q16-10-extra", ver:"8:7.1.1.43+dfsg1-1+deb13u6", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-7.q16-dev", ver:"8:7.1.1.43+dfsg1-1+deb13u6", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-7.q16hdri-10", ver:"8:7.1.1.43+dfsg1-1+deb13u6", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-7.q16hdri-10-extra", ver:"8:7.1.1.43+dfsg1-1+deb13u6", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-7.q16hdri-dev", ver:"8:7.1.1.43+dfsg1-1+deb13u6", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-dev", ver:"8:7.1.1.43+dfsg1-1+deb13u6", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-7-headers", ver:"8:7.1.1.43+dfsg1-1+deb13u6", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-7.q16-10", ver:"8:7.1.1.43+dfsg1-1+deb13u6", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-7.q16-dev", ver:"8:7.1.1.43+dfsg1-1+deb13u6", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-7.q16hdri-10", ver:"8:7.1.1.43+dfsg1-1+deb13u6", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-7.q16hdri-dev", ver:"8:7.1.1.43+dfsg1-1+deb13u6", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-dev", ver:"8:7.1.1.43+dfsg1-1+deb13u6", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perlmagick", ver:"8:7.1.1.43+dfsg1-1+deb13u6", rls:"DEB13"))) {
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
