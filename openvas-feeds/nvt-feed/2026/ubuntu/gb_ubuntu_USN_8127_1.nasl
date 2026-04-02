# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8127.1");
  script_cve_id("CVE-2026-23952", "CVE-2026-25795", "CVE-2026-25796", "CVE-2026-25798", "CVE-2026-25799", "CVE-2026-25970", "CVE-2026-25988", "CVE-2026-26066", "CVE-2026-30883", "CVE-2026-32636");
  script_tag(name:"creation_date", value:"2026-04-01 04:57:46 +0000 (Wed, 01 Apr 2026)");
  script_version("2026-04-01T06:13:16+0000");
  script_tag(name:"last_modification", value:"2026-04-01 06:13:16 +0000 (Wed, 01 Apr 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-13 17:10:28 +0000 (Fri, 13 Mar 2026)");

  script_name("Ubuntu: Security Advisory (USN-8127-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-8127-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8127-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'imagemagick' package(s) announced via the USN-8127-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that ImageMagick did not properly process certain tags
prior to an image being loaded. An attacker could possibly use this issue
to cause ImageMagick to crash, resulting in a denial of service.
(CVE-2026-23952)

It was discovered that ImageMagick did not properly handle temporary file
creation failures. An attacker could possibly use this issue to cause
ImageMagick to crash, resulting in a denial of service. (CVE-2026-25795)

It was discovered that ImageMagick did not properly manage memory under
certain conditions. An attacker could possibly use this issue to cause
ImageMagick to consume resources, resulting in a denial of service.
(CVE-2026-25796)

It was discovered that ImageMagick incorrectly handled certain specially
crafted image files. An attacker could possibly use this issue to cause
ImageMagick to crash, resulting in a denial of service. (CVE-2026-25798)

It was discovered that ImageMagick did not properly validate certain YUV
sampling factors. An attacker could possibly use this issue to cause
ImageMagick to crash, resulting in a denial of service. (CVE-2026-25799)

It was discovered that ImageMagick incorrectly handled certain specially
crafted image files. An attacker could possibly use this issue to cause
ImageMagick to crash, resulting in a denial of service. This issue only
affected Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, Ubuntu 20.04 LTS,
Ubuntu 22.04 LTS and Ubuntu 24.04 LTS. (CVE-2026-25970)

It was discovered that ImageMagick incorrectly managed memory when handling
certain specially crafted image files. An attacker could possibly use this
issue to cause ImageMagick to consume resources, resulting in a denial of
service. (CVE-2026-25988)

It was discovered that ImageMagick incorrectly handled certain crafted image
profiles. An attacker could possibly use this issue to cause ImageMagick
to consume available resources, resulting in a denial of service.
(CVE-2026-26066)

It was discovered that ImageMagick incorrectly handled large image profiles
when encoding PNG images. An attacker could use this issue to cause
ImageMagick to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2026-30883)

Kamil Frankowicz discovered that ImageMagick incorrectly handled certain XML
data. An attacker could possibly use this issue to cause ImageMagick to crash,
resulting in a denial of service. (CVE-2026-32636)");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick", ver:"8:6.7.7.10-6ubuntu3.13+esm20", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-common", ver:"8:6.7.7.10-6ubuntu3.13+esm20", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++5", ver:"8:6.7.7.10-6ubuntu3.13+esm20", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore5", ver:"8:6.7.7.10-6ubuntu3.13+esm20", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore5-extra", ver:"8:6.7.7.10-6ubuntu3.13+esm20", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand5", ver:"8:6.7.7.10-6ubuntu3.13+esm20", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perlmagick", ver:"8:6.7.7.10-6ubuntu3.13+esm20", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6.q16", ver:"8:6.8.9.9-7ubuntu5.16+esm19", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-q16-perl", ver:"8:6.8.9.9-7ubuntu5.16+esm19", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16-5v5", ver:"8:6.8.9.9-7ubuntu5.16+esm19", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-2", ver:"8:6.8.9.9-7ubuntu5.16+esm19", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-2-extra", ver:"8:6.8.9.9-7ubuntu5.16+esm19", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6-headers", ver:"8:6.8.9.9-7ubuntu5.16+esm19", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6.q16-2", ver:"8:6.8.9.9-7ubuntu5.16+esm19", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6.q16", ver:"8:6.9.7.4+dfsg-16ubuntu6.15+esm11", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6.q16hdri", ver:"8:6.9.7.4+dfsg-16ubuntu6.15+esm11", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-q16-perl", ver:"8:6.9.7.4+dfsg-16ubuntu6.15+esm11", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-q16hdri-perl", ver:"8:6.9.7.4+dfsg-16ubuntu6.15+esm11", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16-7", ver:"8:6.9.7.4+dfsg-16ubuntu6.15+esm11", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16hdri-7", ver:"8:6.9.7.4+dfsg-16ubuntu6.15+esm11", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-3", ver:"8:6.9.7.4+dfsg-16ubuntu6.15+esm11", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-3-extra", ver:"8:6.9.7.4+dfsg-16ubuntu6.15+esm11", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16hdri-3", ver:"8:6.9.7.4+dfsg-16ubuntu6.15+esm11", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16hdri-3-extra", ver:"8:6.9.7.4+dfsg-16ubuntu6.15+esm11", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6.q16-3", ver:"8:6.9.7.4+dfsg-16ubuntu6.15+esm11", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6.q16hdri-3", ver:"8:6.9.7.4+dfsg-16ubuntu6.15+esm11", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-q16-perl", ver:"8:6.9.10.23+dfsg-2.1ubuntu11.11+esm9", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-q16hdri-perl", ver:"8:6.9.10.23+dfsg-2.1ubuntu11.11+esm9", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-6", ver:"8:6.9.10.23+dfsg-2.1ubuntu11.11+esm9", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-6-extra", ver:"8:6.9.10.23+dfsg-2.1ubuntu11.11+esm9", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16hdri-6", ver:"8:6.9.10.23+dfsg-2.1ubuntu11.11+esm9", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16hdri-6-extra", ver:"8:6.9.10.23+dfsg-2.1ubuntu11.11+esm9", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6.q16", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.5+esm9", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6.q16hdri", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.5+esm9", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-q16-perl", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.5+esm9", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-q16hdri-perl", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.5+esm9", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16-8", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.5+esm9", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16hdri-8", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.5+esm9", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-6", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.5+esm9", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-6-extra", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.5+esm9", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16hdri-6", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.5+esm9", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16hdri-6-extra", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.5+esm9", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6.q16-6", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.5+esm9", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6.q16hdri-6", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.5+esm9", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6.q16", ver:"8:6.9.12.98+dfsg1-5.2ubuntu0.1~esm8", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6.q16hdri", ver:"8:6.9.12.98+dfsg1-5.2ubuntu0.1~esm8", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-q16-perl", ver:"8:6.9.12.98+dfsg1-5.2ubuntu0.1~esm8", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-q16hdri-perl", ver:"8:6.9.12.98+dfsg1-5.2ubuntu0.1~esm8", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16-9t64", ver:"8:6.9.12.98+dfsg1-5.2ubuntu0.1~esm8", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16hdri-9t64", ver:"8:6.9.12.98+dfsg1-5.2ubuntu0.1~esm8", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6-headers", ver:"8:6.9.12.98+dfsg1-5.2ubuntu0.1~esm8", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-7-extra", ver:"8:6.9.12.98+dfsg1-5.2ubuntu0.1~esm8", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-7t64", ver:"8:6.9.12.98+dfsg1-5.2ubuntu0.1~esm8", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16hdri-7-extra", ver:"8:6.9.12.98+dfsg1-5.2ubuntu0.1~esm8", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16hdri-7t64", ver:"8:6.9.12.98+dfsg1-5.2ubuntu0.1~esm8", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6.q16-7t64", ver:"8:6.9.12.98+dfsg1-5.2ubuntu0.1~esm8", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6.q16hdri-7t64", ver:"8:6.9.12.98+dfsg1-5.2ubuntu0.1~esm8", rls:"UBUNTU24.04 LTS"))) {
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
