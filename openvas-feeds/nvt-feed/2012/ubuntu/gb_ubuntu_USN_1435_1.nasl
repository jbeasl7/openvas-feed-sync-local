# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840996");
  script_cve_id("CVE-2012-0247", "CVE-2012-0248", "CVE-2012-0259", "CVE-2012-1185", "CVE-2012-1186", "CVE-2012-1610", "CVE-2012-1798");
  script_tag(name:"creation_date", value:"2012-05-04 05:17:56 +0000 (Fri, 04 May 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2012-06-06 14:05:00 +0000 (Wed, 06 Jun 2012)");

  script_name("Ubuntu: Security Advisory (USN-1435-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|11\.04|11\.10|12\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-1435-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1435-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'imagemagick' package(s) announced via the USN-1435-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Joonas Kuorilehto and Aleksis Kauppinen discovered that ImageMagick
incorrectly handled certain ResolutionUnit tags. If a user or automated
system using ImageMagick were tricked into opening a specially crafted
image, an attacker could exploit this to cause a denial of service or
possibly execute code with the privileges of the user invoking the program.
(CVE-2012-0247, CVE-2012-1185)

Joonas Kuorilehto and Aleksis Kauppinen discovered that ImageMagick
incorrectly handled certain IFD structures. If a user or automated
system using ImageMagick were tricked into opening a specially crafted
image, an attacker could exploit this to cause a denial of service.
(CVE-2012-0248, CVE-2012-1186)

Aleksis Kauppinen, Joonas Kuorilehto and Tuomas Parttimaa discovered that
ImageMagick incorrectly handled certain JPEG EXIF tags. If a user or
automated system using ImageMagick were tricked into opening a specially
crafted image, an attacker could exploit this to cause a denial of service.
(CVE-2012-0259)

It was discovered that ImageMagick incorrectly handled certain JPEG EXIF
tags. If a user or automated system using ImageMagick were tricked into
opening a specially crafted image, an attacker could exploit this to cause
a denial of service or possibly execute code with the privileges of the
user invoking the program. (CVE-2012-1610)

Aleksis Kauppinen, Joonas Kuorilehto and Tuomas Parttimaa discovered that
ImageMagick incorrectly handled certain TIFF EXIF tags. If a user or
automated system using ImageMagick were tricked into opening a specially
crafted image, an attacker could exploit this to cause a denial of service
or possibly execute code with the privileges of the user invoking the
program. (CVE-2012-1798)");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Ubuntu 10.04, Ubuntu 11.04, Ubuntu 11.10, Ubuntu 12.04.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick", ver:"7:6.5.7.8-1ubuntu1.2", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++2", ver:"7:6.5.7.8-1ubuntu1.2", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick", ver:"7:6.6.2.6-1ubuntu4.1", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++3", ver:"7:6.6.2.6-1ubuntu4.1", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.10") {

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick", ver:"8:6.6.0.4-3ubuntu1.1", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++3", ver:"8:6.6.0.4-3ubuntu1.1", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick", ver:"8:6.6.9.7-5ubuntu3.1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++4", ver:"8:6.6.9.7-5ubuntu3.1", rls:"UBUNTU12.04 LTS"))) {
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
