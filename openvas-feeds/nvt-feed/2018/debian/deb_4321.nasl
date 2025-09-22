# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704321");
  script_cve_id("CVE-2017-10794", "CVE-2017-10799", "CVE-2017-10800", "CVE-2017-11102", "CVE-2017-11139", "CVE-2017-11140", "CVE-2017-11403", "CVE-2017-11636", "CVE-2017-11637", "CVE-2017-11638", "CVE-2017-11641", "CVE-2017-11642", "CVE-2017-11643", "CVE-2017-11722", "CVE-2017-12935", "CVE-2017-12936", "CVE-2017-12937", "CVE-2017-13063", "CVE-2017-13064", "CVE-2017-13065", "CVE-2017-13134", "CVE-2017-13737", "CVE-2017-13775", "CVE-2017-13776", "CVE-2017-13777", "CVE-2017-14314", "CVE-2017-14504", "CVE-2017-14733", "CVE-2017-14994", "CVE-2017-14997", "CVE-2017-15238", "CVE-2017-15277", "CVE-2017-15930", "CVE-2017-16352", "CVE-2017-16353", "CVE-2017-16545", "CVE-2017-16547", "CVE-2017-16669", "CVE-2017-17498", "CVE-2017-17500", "CVE-2017-17501", "CVE-2017-17502", "CVE-2017-17503", "CVE-2017-17782", "CVE-2017-17783", "CVE-2017-17912", "CVE-2017-17913", "CVE-2017-17915", "CVE-2017-18219", "CVE-2017-18220", "CVE-2017-18229", "CVE-2017-18230", "CVE-2017-18231", "CVE-2018-5685", "CVE-2018-6799", "CVE-2018-9018");
  script_tag(name:"creation_date", value:"2018-10-15 22:00:00 +0000 (Mon, 15 Oct 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-31 17:50:45 +0000 (Mon, 31 Jul 2017)");

  script_name("Debian: Security Advisory (DSA-4321-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4321-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/DSA-4321-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4321");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/graphicsmagick");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'graphicsmagick' package(s) announced via the DSA-4321-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in GraphicsMagick, a set of command-line applications to manipulate image files, which could result in denial of service or the execution of arbitrary code if malformed image files are processed.

For the stable distribution (stretch), these problems have been fixed in version 1.3.30+hg15796-1~deb9u1.

We recommend that you upgrade your graphicsmagick packages.

For the detailed security status of graphicsmagick please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'graphicsmagick' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick", ver:"1.3.30+hg15796-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick-dbg", ver:"1.3.30+hg15796-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick-imagemagick-compat", ver:"1.3.30+hg15796-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick-libmagick-dev-compat", ver:"1.3.30+hg15796-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphics-magick-perl", ver:"1.3.30+hg15796-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick++-q16-12", ver:"1.3.30+hg15796-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick++1-dev", ver:"1.3.30+hg15796-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick-q16-3", ver:"1.3.30+hg15796-1~deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick1-dev", ver:"1.3.30+hg15796-1~deb9u1", rls:"DEB9"))) {
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
