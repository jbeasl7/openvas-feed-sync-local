# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60574");
  script_cve_id("CVE-2007-6697", "CVE-2008-0544");
  script_tag(name:"creation_date", value:"2008-03-19 19:30:32 +0000 (Wed, 19 Mar 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1493-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.1|4)");

  script_xref(name:"Advisory-ID", value:"DSA-1493-2");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1493-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1493");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sdl-image1.2' package(s) announced via the DSA-1493-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local/remote vulnerabilities have been discovered in the image loading library for the Simple DirectMedia Layer 1.2. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-6697

Gynvael Coldwind discovered a buffer overflow in GIF image parsing, which could result in denial of service and potentially the execution of arbitrary code.

CVE-2008-0544

It was discovered that a buffer overflow in IFF ILBM image parsing could result in denial of service and potentially the execution of arbitrary code.

For the old stable distribution (sarge), these problems have been fixed in version 1.2.4-1etch1. Due to a copy & paste error etch1 was appended to the version number instead of sarge1. Since the update is otherwise technically correct, the update was not rebuilt on the buildd network.

For the stable distribution (etch), these problems have been fixed in version 1.2.5-2+etch1.

We recommend that you upgrade your sdl-image1.2 packages.");

  script_tag(name:"affected", value:"'sdl-image1.2' package(s) on Debian 3.1, Debian 4.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"libsdl-image1.2", ver:"1.2.4-1etch1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsdl-image1.2-dev", ver:"1.2.4-1etch1", rls:"DEB3.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"libsdl-image1.2", ver:"1.2.5-2+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsdl-image1.2-dev", ver:"1.2.5-2+etch1", rls:"DEB4"))) {
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
