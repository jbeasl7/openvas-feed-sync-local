# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68976");
  script_cve_id("CVE-2010-3429", "CVE-2010-4704", "CVE-2010-4705");
  script_tag(name:"creation_date", value:"2011-03-07 15:04:02 +0000 (Mon, 07 Mar 2011)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2165-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2165-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2165-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2165");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ffmpeg-debian' package(s) announced via the DSA-2165-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in FFmpeg coders, which are used by MPlayer and other applications.

CVE-2010-3429

Cesar Bernardini and Felipe Andres Manzano reported an arbitrary offset dereference vulnerability in the libavcodec, in particular in the FLIC file format parser. A specific FLIC file may exploit this vulnerability and execute arbitrary code. Mplayer is also affected by this problem, as well as other software that use this library.

CVE-2010-4704

Greg Maxwell discovered an integer overflow the Vorbis decoder in FFmpeg. A specific Ogg file may exploit this vulnerability and execute arbitrary code.

CVE-2010-4705

A potential integer overflow has been discovered in the Vorbis decoder in FFmpeg.

This upload also fixes an incomplete patch from DSA-2000-1. Michael Gilbert noticed that there was remaining vulnerabilities, which may cause a denial of service and potentially execution of arbitrary code.

For the oldstable distribution (lenny), this problem has been fixed in version 0.svn20080206-18+lenny3.

We recommend that you upgrade your ffmpeg-debian packages.");

  script_tag(name:"affected", value:"'ffmpeg-debian' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"ffmpeg", ver:"0.svn20080206-18+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ffmpeg-dbg", ver:"0.svn20080206-18+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ffmpeg-doc", ver:"0.svn20080206-18+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec-dev", ver:"0.svn20080206-18+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec51", ver:"0.svn20080206-18+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavdevice-dev", ver:"0.svn20080206-18+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavdevice52", ver:"0.svn20080206-18+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat-dev", ver:"0.svn20080206-18+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat52", ver:"0.svn20080206-18+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavutil-dev", ver:"0.svn20080206-18+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavutil49", ver:"0.svn20080206-18+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpostproc-dev", ver:"0.svn20080206-18+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpostproc51", ver:"0.svn20080206-18+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswscale-dev", ver:"0.svn20080206-18+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswscale0", ver:"0.svn20080206-18+lenny3", rls:"DEB5"))) {
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
