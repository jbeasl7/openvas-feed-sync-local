# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892043");
  script_cve_id("CVE-2016-6352", "CVE-2017-2870", "CVE-2017-6312", "CVE-2017-6313", "CVE-2017-6314");
  script_tag(name:"creation_date", value:"2019-12-20 03:00:11 +0000 (Fri, 20 Dec 2019)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-08 20:40:25 +0000 (Fri, 08 Sep 2017)");

  script_name("Debian: Security Advisory (DLA-2043-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-2043-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/DLA-2043-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gdk-pixbuf' package(s) announced via the DLA-2043-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues in gdk-pixbuf, a library to handle pixbuf, have been found.

CVE-2016-6352

fix for denial of service (out-of-bounds write and crash) via crafted dimensions in an ICO file

CVE-2017-2870

Fix for an exploitable integer overflow vulnerability in the tiff_image_parse functionality. When software is compiled with clang, A specially crafted tiff file can cause a heap-overflow resulting in remote code execution. Debian package is compiled with gcc and is not affected, but probably some downstream is.

CVE-2017-6312

Fix for an integer overflow in io-ico.c that allows attackers to cause a denial of service (segmentation fault and application crash) via a crafted image

CVE-2017-6313

Fix for an integer underflow in the load_resources function in io-icns.c that allows attackers to cause a denial of service (out-of-bounds read and program crash) via a crafted image entry size in an ICO file

CVE-2017-6314

Fix for an infinite loop in the make_available_at_least function in io-tiff.c that allows attackers to cause a denial of service via a large TIFF file.

For Debian 8 Jessie, these problems have been fixed in version 2.31.1-2+deb8u8.

We recommend that you upgrade your gdk-pixbuf packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'gdk-pixbuf' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-gdkpixbuf-2.0", ver:"2.31.1-2+deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgdk-pixbuf2.0-0", ver:"2.31.1-2+deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgdk-pixbuf2.0-0-dbg", ver:"2.31.1-2+deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgdk-pixbuf2.0-0-udeb", ver:"2.31.1-2+deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgdk-pixbuf2.0-common", ver:"2.31.1-2+deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgdk-pixbuf2.0-dev", ver:"2.31.1-2+deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgdk-pixbuf2.0-doc", ver:"2.31.1-2+deb8u8", rls:"DEB8"))) {
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
