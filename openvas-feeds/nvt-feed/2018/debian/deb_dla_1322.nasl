# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891322");
  script_cve_id("CVE-2017-18219", "CVE-2017-18220", "CVE-2017-18229", "CVE-2017-18230", "CVE-2017-18231", "CVE-2018-9018");
  script_tag(name:"creation_date", value:"2018-03-28 22:00:00 +0000 (Wed, 28 Mar 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-27 14:50:06 +0000 (Tue, 27 Mar 2018)");

  script_name("Debian: Security Advisory (DLA-1322-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-1322-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/DLA-1322-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'graphicsmagick' package(s) announced via the DLA-1322-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Various security issues were discovered in Graphicsmagick, a collection of image processing tools.

CVE-2017-18219

An allocation failure vulnerability was found in the function ReadOnePNGImage in coders/png.c, which allows attackers to cause a denial of service via a crafted file that triggers an attempt at a large png_pixels array allocation.

CVE-2017-18220

The ReadOneJNGImage and ReadJNGImage functions in coders/png.c allow remote attackers to cause a denial of service or possibly have unspecified other impact via a crafted file, a related issue to CVE-2017-11403.

CVE-2017-18229

An allocation failure vulnerability was found in the function ReadTIFFImage in coders/tiff.c, which allows attackers to cause a denial of service via a crafted file, because file size is not properly used to restrict scanline, strip, and tile allocations.

CVE-2017-18230

A NULL pointer dereference vulnerability was found in the function ReadCINEONImage in coders/cineon.c, which allows attackers to cause a denial of service via a crafted file.

CVE-2017-18231

A NULL pointer dereference vulnerability was found in the function ReadEnhMetaFile in coders/emf.c, which allows attackers to cause a denial of service via a crafted file.

CVE-2018-9018

There is a divide-by-zero error in the ReadMNGImage function of coders/png.c. Remote attackers could leverage this vulnerability to cause a crash and denial of service via a crafted mng file.

For Debian 7 Wheezy, these problems have been fixed in version 1.3.16-1.1+deb7u19.

We recommend that you upgrade your graphicsmagick packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'graphicsmagick' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick", ver:"1.3.16-1.1+deb7u19", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick-dbg", ver:"1.3.16-1.1+deb7u19", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick-imagemagick-compat", ver:"1.3.16-1.1+deb7u19", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick-libmagick-dev-compat", ver:"1.3.16-1.1+deb7u19", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphics-magick-perl", ver:"1.3.16-1.1+deb7u19", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick++1-dev", ver:"1.3.16-1.1+deb7u19", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick++3", ver:"1.3.16-1.1+deb7u19", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick1-dev", ver:"1.3.16-1.1+deb7u19", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick3", ver:"1.3.16-1.1+deb7u19", rls:"DEB7"))) {
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
