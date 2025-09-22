# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53749");
  script_cve_id("CVE-2005-0397", "CVE-2005-0759", "CVE-2005-0760", "CVE-2005-0762");
  script_tag(name:"creation_date", value:"2008-01-17 22:00:53 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-702-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-702-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/DSA-702-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-702");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'imagemagick' package(s) announced via the DSA-702-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in ImageMagick, a commonly used image manipulation library. These problems can be exploited by a carefully crafted graphic image. The Common Vulnerabilities and Exposures project identifies the following problems:

CAN-2005-0397

Tavis Ormandy discovered a format string vulnerability in the filename handling code which allows a remote attacker to cause a denial of service and possibly execute arbitrary code.

CAN-2005-0759

Andrei Nigmatulin discovered a denial of service condition which can be caused by an invalid tag in a TIFF image.

CAN-2005-0760

Andrei Nigmatulin discovered that the TIFF decoder is vulnerable to accessing memory out of bounds which will result in a segmentation fault.

CAN-2005-0762

Andrei Nigmatulin discovered a buffer overflow in the SGI parser which allows a remote attacker to execute arbitrary code via a specially crafted SGI image file.

For the stable distribution (woody) these problems have been fixed in version 5.4.4.5-1woody6.

For the unstable distribution (sid) these problems have been fixed in version 6.0.6.2-2.2.

We recommend that you upgrade your imagemagick package.");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Debian 3.0.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick", ver:"4:5.4.4.5-1woody6", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++5", ver:"4:5.4.4.5-1woody6", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++5-dev", ver:"4:5.4.4.5-1woody6", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick5", ver:"4:5.4.4.5-1woody6", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick5-dev", ver:"4:5.4.4.5-1woody6", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perlmagick", ver:"4:5.4.4.5-1woody6", rls:"DEB3.0"))) {
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
