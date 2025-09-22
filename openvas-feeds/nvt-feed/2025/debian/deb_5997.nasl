# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2025.5997");
  script_cve_id("CVE-2025-55154", "CVE-2025-55212", "CVE-2025-55298", "CVE-2025-57803", "CVE-2025-57807");
  script_tag(name:"creation_date", value:"2025-09-12 06:18:36 +0000 (Fri, 12 Sep 2025)");
  script_version("2025-09-15T05:39:20+0000");
  script_tag(name:"last_modification", value:"2025-09-15 05:39:20 +0000 (Mon, 15 Sep 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-10 15:31:10 +0000 (Wed, 10 Sep 2025)");

  script_name("Debian: Security Advisory (DSA-5997-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(12|13)");

  script_xref(name:"Advisory-ID", value:"DSA-5997-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2025/DSA-5997-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'imagemagick' package(s) announced via the DSA-5997-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Debian 12, Debian 13.");

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

if(release == "DEB12") {

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6-common", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6-doc", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6.q16", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6.q16hdri", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-common", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-doc", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-perl", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-q16-perl", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-q16hdri-perl", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6-headers", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16-8", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16-dev", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16hdri-8", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16hdri-dev", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-dev", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6-arch-config", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6-headers", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-6", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-6-extra", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-dev", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16hdri-6", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16hdri-6-extra", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16hdri-dev", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-dev", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6-headers", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6.q16-6", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6.q16-dev", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6.q16hdri-6", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6.q16hdri-dev", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-dev", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perlmagick", ver:"8:6.9.11.60+dfsg-1.6+deb12u4", rls:"DEB12"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB13") {

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick", ver:"8:7.1.1.43+dfsg1-1+deb13u2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-7-common", ver:"8:7.1.1.43+dfsg1-1+deb13u2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-7-doc", ver:"8:7.1.1.43+dfsg1-1+deb13u2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-7.q16", ver:"8:7.1.1.43+dfsg1-1+deb13u2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-7.q16hdri", ver:"8:7.1.1.43+dfsg1-1+deb13u2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-perl", ver:"8:7.1.1.43+dfsg1-1+deb13u2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-q16-perl", ver:"8:7.1.1.43+dfsg1-1+deb13u2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-q16hdri-perl", ver:"8:7.1.1.43+dfsg1-1+deb13u2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-7-headers", ver:"8:7.1.1.43+dfsg1-1+deb13u2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-7.q16-5", ver:"8:7.1.1.43+dfsg1-1+deb13u2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-7.q16-dev", ver:"8:7.1.1.43+dfsg1-1+deb13u2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-7.q16hdri-5", ver:"8:7.1.1.43+dfsg1-1+deb13u2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-7.q16hdri-dev", ver:"8:7.1.1.43+dfsg1-1+deb13u2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-dev", ver:"8:7.1.1.43+dfsg1-1+deb13u2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-7-arch-config", ver:"8:7.1.1.43+dfsg1-1+deb13u2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-7-headers", ver:"8:7.1.1.43+dfsg1-1+deb13u2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-7.q16-10", ver:"8:7.1.1.43+dfsg1-1+deb13u2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-7.q16-10-extra", ver:"8:7.1.1.43+dfsg1-1+deb13u2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-7.q16-dev", ver:"8:7.1.1.43+dfsg1-1+deb13u2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-7.q16hdri-10", ver:"8:7.1.1.43+dfsg1-1+deb13u2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-7.q16hdri-10-extra", ver:"8:7.1.1.43+dfsg1-1+deb13u2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-7.q16hdri-dev", ver:"8:7.1.1.43+dfsg1-1+deb13u2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-dev", ver:"8:7.1.1.43+dfsg1-1+deb13u2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-7-headers", ver:"8:7.1.1.43+dfsg1-1+deb13u2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-7.q16-10", ver:"8:7.1.1.43+dfsg1-1+deb13u2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-7.q16-dev", ver:"8:7.1.1.43+dfsg1-1+deb13u2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-7.q16hdri-10", ver:"8:7.1.1.43+dfsg1-1+deb13u2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-7.q16hdri-dev", ver:"8:7.1.1.43+dfsg1-1+deb13u2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-dev", ver:"8:7.1.1.43+dfsg1-1+deb13u2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perlmagick", ver:"8:7.1.1.43+dfsg1-1+deb13u2", rls:"DEB13"))) {
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
