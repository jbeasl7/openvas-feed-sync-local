# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64255");
  script_cve_id("CVE-2008-1768", "CVE-2008-1769", "CVE-2008-1881", "CVE-2008-2147", "CVE-2008-2430", "CVE-2008-3794", "CVE-2008-4686", "CVE-2008-5032");
  script_tag(name:"creation_date", value:"2009-06-23 13:49:15 +0000 (Tue, 23 Jun 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1819-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1819-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1819-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1819");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'vlc' package(s) announced via the DSA-1819-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in vlc, a multimedia player and streamer. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-1768

Drew Yao discovered that multiple integer overflows in the MP4 demuxer, Real demuxer and Cinepak codec can lead to the execution of arbitrary code.

CVE-2008-1769

Drew Yao discovered that the Cinepak codec is prone to a memory corruption, which can be triggered by a crafted Cinepak file.

CVE-2008-1881

Luigi Auriemma discovered that it is possible to execute arbitrary code via a long subtitle in an SSA file.

CVE-2008-2147

It was discovered that vlc is prone to a search path vulnerability, which allows local users to perform privilege escalations.

CVE-2008-2430

Alin Rad Pop discovered that it is possible to execute arbitrary code when opening a WAV file containing a large fmt chunk.

CVE-2008-3794

Pinar Yanardag discovered that it is possible to execute arbitrary code when opening a crafted mmst link.

CVE-2008-4686

Tobias Klein discovered that it is possible to execute arbitrary code when opening a crafted .ty file.

CVE-2008-5032

Tobias Klein discovered that it is possible to execute arbitrary code when opening an invalid CUE image file with a crafted header.

For the oldstable distribution (etch), these problems have been fixed in version 0.8.6-svn20061012.debian-5.1+etch3.

For the stable distribution (lenny), these problems have been fixed in version 0.8.6.h-4+lenny2, which was already included in the lenny release.

For the testing distribution (squeeze) and the unstable distribution (sid), these problems have been fixed in version 0.8.6.h-5.

We recommend that you upgrade your vlc packages.");

  script_tag(name:"affected", value:"'vlc' package(s) on Debian 4.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"libvlc0", ver:"0.8.6-svn20061012.debian-5.1+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvlc0-dev", ver:"0.8.6-svn20061012.debian-5.1+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-plugin-vlc", ver:"0.8.6-svn20061012.debian-5.1+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc", ver:"0.8.6-svn20061012.debian-5.1+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-nox", ver:"0.8.6-svn20061012.debian-5.1+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-alsa", ver:"0.8.6-svn20061012.debian-5.1+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-arts", ver:"0.8.6-svn20061012.debian-5.1+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-esd", ver:"0.8.6-svn20061012.debian-5.1+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-ggi", ver:"0.8.6-svn20061012.debian-5.1+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-glide", ver:"0.8.6-svn20061012.debian-5.1+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-sdl", ver:"0.8.6-svn20061012.debian-5.1+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vlc-plugin-svgalib", ver:"0.8.6-svn20061012.debian-5.1+etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wxvlc", ver:"0.8.6-svn20061012.debian-5.1+etch3", rls:"DEB4"))) {
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
