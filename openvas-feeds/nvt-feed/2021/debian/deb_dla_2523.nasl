# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892523");
  script_cve_id("CVE-2017-14528", "CVE-2020-19667", "CVE-2020-25665", "CVE-2020-25674", "CVE-2020-27560", "CVE-2020-27750", "CVE-2020-27760", "CVE-2020-27763", "CVE-2020-27765", "CVE-2020-27773", "CVE-2020-29599");
  script_tag(name:"creation_date", value:"2021-01-13 04:00:30 +0000 (Wed, 13 Jan 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-28 15:25:41 +0000 (Mon, 28 Dec 2020)");

  script_name("Debian: Security Advisory (DLA-2523-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2523-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/DLA-2523-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/imagemagick");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'imagemagick' package(s) announced via the DLA-2523-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities were found in ImageMagick, a suite of image manipulation programs. An attacker could cause denial of service and execution of arbitrary code when a crafted image file is processed.

CVE-2017-14528

The TIFFSetProfiles function in coders/tiff.c has incorrect expectations about whether LibTIFF TIFFGetField return values imply that data validation has occurred, which allows remote attackers to cause a denial of service (use-after-free after an invalid call to TIFFSetField, and application crash) via a crafted file.

CVE-2020-19667

Stack-based buffer overflow and unconditional jump in ReadXPMImage in coders/xpm.c

CVE-2020-25665

The PALM image coder at coders/palm.c makes an improper call to AcquireQuantumMemory() in routine WritePALMImage() because it needs to be offset by 256. This can cause a out-of-bounds read later on in the routine. This could cause impact to reliability.

CVE-2020-25674

WriteOnePNGImage() from coders/png.c (the PNG coder) has a for loop with an improper exit condition that can allow an out-of-bounds READ via heap-buffer-overflow. This occurs because it is possible for the colormap to have less than 256 valid values but the loop condition will loop 256 times, attempting to pass invalid colormap data to the event logger.

CVE-2020-27560

ImageMagick allows Division by Zero in OptimizeLayerFrames in MagickCore/layer.c, which may cause a denial of service.

CVE-2020-27750

A flaw was found in MagickCore/colorspace-private.h and MagickCore/quantum.h. An attacker who submits a crafted file that is processedcould trigger undefined behavior in the form of values outside the range of type `unsigned char` and math division by zero. This would most likely lead to an impact to application availability, but could potentially cause other problems related to undefined behavior.

CVE-2020-27760

In `GammaImage()` of /MagickCore/enhance.c, depending on the `gamma` value, it's possible to trigger a divide-by-zero condition when a crafted input file is processed by ImageMagick. This could lead to an impact to application availability.

CVE-2020-27763

A flaw was found in MagickCore/resize.c. An attacker who submits a crafted file that is processed by ImageMagick could trigger undefined behavior in the form of math division by zero. This would most likely lead to an impact to application availability, but could potentially cause other problems related to undefined behavior.

CVE-2020-27765

A flaw was found in MagickCore/segment.c. An attacker who submits a crafted file that is processed by ImageMagick could trigger undefined behavior in the form of math division by zero. This would most likely lead to an impact to application availability, but could potentially cause other problems related to undefined behavior.

CVE-2020-27773

A flaw was found in MagickCore/gem-private.h. An attacker who submits a crafted file that is processed by ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6-common", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6-doc", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6.q16", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6.q16hdri", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-common", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-doc", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-perl", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-q16-perl", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-q16hdri-perl", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6-headers", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16-7", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16-dev", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16hdri-7", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16hdri-dev", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-dev", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6-arch-config", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6-headers", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-3", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-3-extra", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-dev", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16hdri-3", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16hdri-3-extra", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16hdri-dev", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-dev", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6-headers", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6.q16-3", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6.q16-dev", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6.q16hdri-3", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6.q16hdri-dev", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-dev", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perlmagick", ver:"8:6.9.7.4+dfsg-11+deb9u11", rls:"DEB9"))) {
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
