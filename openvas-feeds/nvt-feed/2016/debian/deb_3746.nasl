# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703746");
  script_cve_id("CVE-2015-8808", "CVE-2016-2317", "CVE-2016-2318", "CVE-2016-3714", "CVE-2016-3715", "CVE-2016-5118", "CVE-2016-5240", "CVE-2016-7800", "CVE-2016-7996", "CVE-2016-7997", "CVE-2016-8682", "CVE-2016-8683", "CVE-2016-8684", "CVE-2016-9830");
  script_tag(name:"creation_date", value:"2016-12-23 23:00:00 +0000 (Fri, 23 Dec 2016)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-19 15:29:11 +0000 (Thu, 19 Jan 2017)");

  script_name("Debian: Security Advisory (DSA-3746-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3746-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3746-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3746");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'graphicsmagick' package(s) announced via the DSA-3746-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in GraphicsMagick, a collection of image processing tool, which can cause denial of service attacks, remote file deletion, and remote command execution.

This security update removes the full support of PLT/Gnuplot decoder to prevent Gnuplot-shell based shell exploits for fixing the CVE-2016-3714 vulnerability.

The undocumented TMP magick prefix no longer removes the argument file after it has been read for fixing the CVE-2016-3715 vulnerability. Since the TMP feature was originally implemented, GraphicsMagick added a temporary file management subsystem which assures that temporary files are removed so this feature is not needed.

Remove support for reading input from a shell command, or writing output to a shell command, by prefixing the specified filename (containing the command) with a '<pipe>' for fixing the CVE-2016-5118 vulnerability.

CVE-2015-8808

Gustavo Grieco discovered an out of bound read in the parsing of GIF files which may cause denial of service.

CVE-2016-2317

Gustavo Grieco discovered a stack buffer overflow and two heap buffer overflows while processing SVG images which may cause denial of service.

CVE-2016-2318

Gustavo Grieco discovered several segmentation faults while processing SVG images which may cause denial of service.

CVE-2016-5240

Gustavo Grieco discovered an endless loop problem caused by negative stroke-dasharray arguments while parsing SVG files which may cause denial of service.

CVE-2016-7800

Marco Grassi discovered an unsigned underflow leading to heap overflow when parsing 8BIM chunk often attached to JPG files which may cause denial of service.

CVE-2016-7996

Moshe Kaplan discovered that there is no check that the provided colormap is not larger than 256 entries in the WPG reader which may cause denial of service.

CVE-2016-7997

Moshe Kaplan discovered that an assertion is thrown for some files in the WPG reader due to a logic error which may cause denial of service.

CVE-2016-8682

Agostino Sarubbo of Gentoo discovered a stack buffer read overflow while reading the SCT header which may cause denial of service.

CVE-2016-8683

Agostino Sarubbo of Gentoo discovered a memory allocation failure in the PCX coder which may cause denial of service.

CVE-2016-8684

Agostino Sarubbo of Gentoo discovered a memory allocation failure in the SGI coder which may cause denial of service.

CVE-2016-9830

Agostino Sarubbo of Gentoo discovered a memory allocation failure in MagickRealloc() function which may cause denial of service.

For the stable distribution (jessie), these problems have been fixed in version 1.3.20-3+deb8u2.

For the testing distribution (stretch), these problems (with the exception of CVE-2016-9830) have been fixed in version 1.3.25-5.

For the unstable distribution (sid), these problems have been fixed in version 1.3.25-6.

We recommend that you upgrade your graphicsmagick packages.");

  script_tag(name:"affected", value:"'graphicsmagick' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick", ver:"1.3.20-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick-dbg", ver:"1.3.20-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick-imagemagick-compat", ver:"1.3.20-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick-libmagick-dev-compat", ver:"1.3.20-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphics-magick-perl", ver:"1.3.20-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick++1-dev", ver:"1.3.20-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick++3", ver:"1.3.20-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick1-dev", ver:"1.3.20-3+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick3", ver:"1.3.20-3+deb8u2", rls:"DEB8"))) {
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
