# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64637");
  script_cve_id("CVE-2007-1667", "CVE-2007-1797", "CVE-2007-4985", "CVE-2007-4986", "CVE-2007-4987", "CVE-2007-4988", "CVE-2008-1096", "CVE-2008-1097", "CVE-2009-1882");
  script_tag(name:"creation_date", value:"2009-08-17 14:54:45 +0000 (Mon, 17 Aug 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 02:45:07 +0000 (Fri, 02 Feb 2024)");

  script_name("Debian: Security Advisory (DSA-1858-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1858-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1858-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1858");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'imagemagick' package(s) announced via the DSA-1858-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the imagemagick image manipulation programs which can lead to the execution of arbitrary code, exposure of sensitive information or cause DoS. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-1667

Multiple integer overflows in XInitImage function in xwd.c for ImageMagick, allow user-assisted remote attackers to cause a denial of service (crash) or obtain sensitive information via crafted images with large or negative values that trigger a buffer overflow. It only affects the oldstable distribution (etch).

CVE-2007-1797

Multiple integer overflows allow remote attackers to execute arbitrary code via a crafted DCM image, or the colors or comments field in a crafted XWD image. It only affects the oldstable distribution (etch).

CVE-2007-4985

A crafted image file can trigger an infinite loop in the ReadDCMImage function or in the ReadXCFImage function. It only affects the oldstable distribution (etch).

CVE-2007-4986

Multiple integer overflows allow context-dependent attackers to execute arbitrary code via a crafted .dcm, .dib, .xbm, .xcf, or .xwd image file, which triggers a heap-based buffer overflow. It only affects the oldstable distribution (etch).

CVE-2007-4987

Off-by-one error allows context-dependent attackers to execute arbitrary code via a crafted image file, which triggers the writing of a '0' character to an out-of-bounds address. It affects only the oldstable distribution (etch).

CVE-2007-4988

A sign extension error allows context-dependent attackers to execute arbitrary code via a crafted width value in an image file, which triggers an integer overflow and a heap-based buffer overflow. It affects only the oldstable distribution (etch).

CVE-2008-1096

The load_tile function in the XCF coder allows user-assisted remote attackers to cause a denial of service or possibly execute arbitrary code via a crafted .xcf file that triggers an out-of-bounds heap write. It affects only to oldstable (etch).

CVE-2008-1097

Heap-based buffer overflow in the PCX coder allows user-assisted remote attackers to cause a denial of service or possibly execute arbitrary code via a crafted .pcx file that triggers incorrect memory allocation for the scanline array, leading to memory corruption. It affects only to oldstable (etch).

CVE-2009-1882

Integer overflow allows remote attackers to cause a denial of service (crash) and possibly execute arbitrary code via a crafted TIFF file, which triggers a buffer overflow.

For the old stable distribution (etch), these problems have been fixed in version 7:6.2.4.5.dfsg1-0.15+etch1.

For the stable distribution (lenny), these problems have been fixed in version 7:6.3.7.9.dfsg2-1~lenny3.

For the upcoming stable distribution (squeeze) and the unstable distribution (sid), these problems have been fixed in version 7:6.5.1.0-1.1.

We recommend that you upgrade your imagemagick packages.");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Debian 4, Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick", ver:"7:6.2.4.5.dfsg1-0.15+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++9-dev", ver:"7:6.2.4.5.dfsg1-0.15+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++9c2a", ver:"7:6.2.4.5.dfsg1-0.15+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick9", ver:"7:6.2.4.5.dfsg1-0.15+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick9-dev", ver:"7:6.2.4.5.dfsg1-0.15+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perlmagick", ver:"7:6.2.4.5.dfsg1-0.15+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick", ver:"7:6.3.7.9.dfsg2-1~lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++10", ver:"7:6.3.7.9.dfsg2-1~lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++9-dev", ver:"7:6.3.7.9.dfsg2-1~lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick10", ver:"7:6.3.7.9.dfsg2-1~lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick9-dev", ver:"7:6.3.7.9.dfsg2-1~lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perlmagick", ver:"7:6.3.7.9.dfsg2-1~lenny3", rls:"DEB5"))) {
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
