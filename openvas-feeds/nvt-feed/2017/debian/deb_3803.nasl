# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703803");
  script_cve_id("CVE-2016-10243");
  script_tag(name:"creation_date", value:"2017-03-07 23:00:00 +0000 (Tue, 07 Mar 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-16 01:21:06 +0000 (Tue, 16 May 2017)");

  script_name("Debian: Security Advisory (DSA-3803-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3803-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-3803-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3803");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'texlive-base' package(s) announced via the DSA-3803-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that texlive-base, the TeX Live package which provides the essential TeX programs and files, whitelists mpost as an external program to be run from within the TeX source code (called write18). Since mpost allows to specify other programs to be run, an attacker can take advantage of this flaw for arbitrary code execution when compiling a TeX document.

For the stable distribution (jessie), this problem has been fixed in version 2014.20141024-2+deb8u1.

For the upcoming stable distribution (stretch), this problem has been fixed in version 2016.20161130-1.

For the unstable distribution (sid), this problem has been fixed in version 2016.20161130-1.

We recommend that you upgrade your texlive-base packages.");

  script_tag(name:"affected", value:"'texlive-base' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"latex-beamer", ver:"2014.20141024-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"latex-xcolor", ver:"2014.20141024-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pgf", ver:"2014.20141024-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"texlive", ver:"2014.20141024-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"texlive-base", ver:"2014.20141024-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"texlive-fonts-recommended", ver:"2014.20141024-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"texlive-fonts-recommended-doc", ver:"2014.20141024-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"texlive-full", ver:"2014.20141024-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"texlive-generic-recommended", ver:"2014.20141024-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"texlive-latex-base", ver:"2014.20141024-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"texlive-latex-base-doc", ver:"2014.20141024-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"texlive-latex-recommended", ver:"2014.20141024-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"texlive-latex-recommended-doc", ver:"2014.20141024-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"texlive-luatex", ver:"2014.20141024-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"texlive-metapost", ver:"2014.20141024-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"texlive-metapost-doc", ver:"2014.20141024-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"texlive-omega", ver:"2014.20141024-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"texlive-pictures", ver:"2014.20141024-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"texlive-pictures-doc", ver:"2014.20141024-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"texlive-xetex", ver:"2014.20141024-2+deb8u1", rls:"DEB8"))) {
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
