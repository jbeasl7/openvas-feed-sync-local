# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61038");
  script_cve_id("CVE-2008-1482", "CVE-2008-1686", "CVE-2008-1878");
  script_tag(name:"creation_date", value:"2008-05-27 13:41:50 +0000 (Tue, 27 May 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1586-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1586-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1586-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1586");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xine-lib' package(s) announced via the DSA-1586-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in xine-lib, a library which supplies most of the application functionality of the xine multimedia player. The Common Vulnerabilities and Exposures project identifies the following three problems:

CVE-2008-1482

Integer overflow vulnerabilities exist in xine's FLV, QuickTime, RealMedia, MVE and CAK demuxers, as well as the EBML parser used by the Matroska demuxer. These weaknesses allow an attacker to overflow heap buffers and potentially execute arbitrary code by supplying a maliciously crafted file of those types.

CVE-2008-1686

Insufficient input validation in the Speex implementation used by this version of xine enables an invalid array access and the execution of arbitrary code by supplying a maliciously crafted Speex file.

CVE-2008-1878

Inadequate bounds checking in the NES Sound Format (NSF) demuxer enables a stack buffer overflow and the execution of arbitrary code through a maliciously crafted NSF file.

For the stable distribution (etch), these problems have been fixed in version 1.1.2+dfsg-7.

For the unstable distribution (sid), these problems have been fixed in version 1.1.12-2.

We recommend that you upgrade your xine-lib packages.");

  script_tag(name:"affected", value:"'xine-lib' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libxine-dev", ver:"1.1.2+dfsg-7", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxine1", ver:"1.1.2+dfsg-7", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxine1-dbg", ver:"1.1.2+dfsg-7", rls:"DEB4"))) {
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
