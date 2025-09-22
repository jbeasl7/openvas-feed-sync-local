# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891861");
  script_cve_id("CVE-2018-3977", "CVE-2019-12216", "CVE-2019-12217", "CVE-2019-12218", "CVE-2019-12219", "CVE-2019-12220", "CVE-2019-12221", "CVE-2019-12222", "CVE-2019-5051", "CVE-2019-5052", "CVE-2019-7635");
  script_tag(name:"creation_date", value:"2019-07-23 02:00:19 +0000 (Tue, 23 Jul 2019)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-10 18:38:33 +0000 (Wed, 10 Jul 2019)");

  script_name("Debian: Security Advisory (DLA-1861-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1861-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/DLA-1861-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libsdl2-image' package(s) announced via the DLA-1861-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The following issues have been found in libsdl2-image, the image file loading library.

CVE-2018-3977

Heap buffer overflow in IMG_xcf.c. This vulnerability might be leveraged by remote attackers to cause remote code execution or denial of service via a crafted XCF file.

CVE-2019-5052

Integer overflow and subsequent buffer overflow in IMG_pcx.c. This vulnerability might be leveraged by remote attackers to cause remote code execution or denial of service via a crafted PCX file.

CVE-2019-7635

Heap buffer overflow affecting Blit1to4, in IMG_bmp.c. This vulnerability might be leveraged by remote attackers to cause denial of service or any other unspecified impact via a crafted BMP file.

CVE-2019-12216 CVE-2019-12217, CVE-2019-12218, CVE-2019-12219, CVE-2019-12220, CVE-2019-12221, CVE-2019-12222 Multiple out-of-bound read and write accesses affecting IMG_LoadPCX_RW, in IMG_pcx.c. These vulnerabilities might be leveraged by remote attackers to cause denial of service or any other unspecified impact via a crafted PCX file.

For Debian 8 Jessie, these problems have been fixed in version 2.0.0+dfsg-3+deb8u2.

We recommend that you upgrade your libsdl2-image packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libsdl2-image' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libsdl2-image-2.0-0", ver:"2.0.0+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsdl2-image-dbg", ver:"2.0.0+dfsg-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsdl2-image-dev", ver:"2.0.0+dfsg-3+deb8u2", rls:"DEB8"))) {
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
