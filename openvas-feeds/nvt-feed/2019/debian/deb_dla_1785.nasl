# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891785");
  script_cve_id("CVE-2017-1000445", "CVE-2017-1000476", "CVE-2017-11446", "CVE-2017-11523", "CVE-2017-11537", "CVE-2017-12140", "CVE-2017-12430", "CVE-2017-12432", "CVE-2017-12435", "CVE-2017-12563", "CVE-2017-12587", "CVE-2017-12643", "CVE-2017-12670", "CVE-2017-12674", "CVE-2017-12691", "CVE-2017-12692", "CVE-2017-12693", "CVE-2017-12875", "CVE-2017-13133", "CVE-2017-13142", "CVE-2017-13145", "CVE-2017-13658", "CVE-2017-13768", "CVE-2017-14060", "CVE-2017-14172", "CVE-2017-14173", "CVE-2017-14174", "CVE-2017-14175", "CVE-2017-14249", "CVE-2017-14341", "CVE-2017-14400", "CVE-2017-14505", "CVE-2017-14532", "CVE-2017-14624", "CVE-2017-14625", "CVE-2017-14626", "CVE-2017-14739", "CVE-2017-14741", "CVE-2017-15015", "CVE-2017-15017", "CVE-2017-15281", "CVE-2017-17682", "CVE-2017-17914", "CVE-2017-18271", "CVE-2017-18273", "CVE-2017-9500", "CVE-2019-10650", "CVE-2019-11597", "CVE-2019-11598", "CVE-2019-9956");
  script_tag(name:"creation_date", value:"2019-05-15 02:01:09 +0000 (Wed, 15 May 2019)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-22 16:29:44 +0000 (Fri, 22 Sep 2017)");

  script_name("Debian: Security Advisory (DLA-1785-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1785-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/DLA-1785-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'imagemagick' package(s) announced via the DLA-1785-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Numerous security vulnerabilities were fixed in Imagemagick. Various memory handling problems and cases of missing or incomplete input sanitizing may result in denial of service, memory or CPU exhaustion, information disclosure or potentially the execution of arbitrary code when a malformed image file is processed.

For Debian 8 Jessie, these problems have been fixed in version 8:6.8.9.9-5+deb8u16.

We recommend that you upgrade your imagemagick packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick", ver:"8:6.8.9.9-5+deb8u16", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6.q16", ver:"8:6.8.9.9-5+deb8u16", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-common", ver:"8:6.8.9.9-5+deb8u16", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-dbg", ver:"8:6.8.9.9-5+deb8u16", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-doc", ver:"8:6.8.9.9-5+deb8u16", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-perl", ver:"8:6.8.9.9-5+deb8u16", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-q16-perl", ver:"8:6.8.9.9-5+deb8u16", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6-headers", ver:"8:6.8.9.9-5+deb8u16", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16-5", ver:"8:6.8.9.9-5+deb8u16", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16-dev", ver:"8:6.8.9.9-5+deb8u16", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-dev", ver:"8:6.8.9.9-5+deb8u16", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6-arch-config", ver:"8:6.8.9.9-5+deb8u16", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6-headers", ver:"8:6.8.9.9-5+deb8u16", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-2", ver:"8:6.8.9.9-5+deb8u16", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-2-extra", ver:"8:6.8.9.9-5+deb8u16", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-dev", ver:"8:6.8.9.9-5+deb8u16", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-dev", ver:"8:6.8.9.9-5+deb8u16", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6-headers", ver:"8:6.8.9.9-5+deb8u16", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6.q16-2", ver:"8:6.8.9.9-5+deb8u16", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6.q16-dev", ver:"8:6.8.9.9-5+deb8u16", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-dev", ver:"8:6.8.9.9-5+deb8u16", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perlmagick", ver:"8:6.8.9.9-5+deb8u16", rls:"DEB8"))) {
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
