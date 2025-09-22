# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63682");
  script_cve_id("CVE-2008-5907", "CVE-2008-6218", "CVE-2009-0040");
  script_tag(name:"creation_date", value:"2009-03-31 17:20:21 +0000 (Tue, 31 Mar 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1750-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1750-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1750-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1750");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libpng' package(s) announced via the DSA-1750-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in libpng, a library for reading and writing PNG files. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-2445

The png_handle_tRNS function allows attackers to cause a denial of service (application crash) via a grayscale PNG image with a bad tRNS chunk CRC value.

CVE-2007-5269

Certain chunk handlers allow attackers to cause a denial of service (crash) via crafted pCAL, sCAL, tEXt, iTXt, and ztXT chunking in PNG images, which trigger out-of-bounds read operations.

CVE-2008-1382

libpng allows context-dependent attackers to cause a denial of service (crash) and possibly execute arbitrary code via a PNG file with zero length 'unknown' chunks, which trigger an access of uninitialized memory.

CVE-2008-5907

The png_check_keyword might allow context-dependent attackers to set the value of an arbitrary memory location to zero via vectors involving creation of crafted PNG files with keywords.

CVE-2008-6218

A memory leak in the png_handle_tEXt function allows context-dependent attackers to cause a denial of service (memory exhaustion) via a crafted PNG file.

CVE-2009-0040

libpng allows context-dependent attackers to cause a denial of service (application crash) or possibly execute arbitrary code via a crafted PNG file that triggers a free of an uninitialized pointer in (1) the png_read_png function, (2) pCAL chunk handling, or (3) setup of 16-bit gamma tables.

For the old stable distribution (etch), these problems have been fixed in version 1.2.15~beta5-1+etch2.

For the stable distribution (lenny), these problems have been fixed in version 1.2.27-2+lenny2. (Only CVE-2008-5907, CVE-2008-5907 and CVE-2009-0040 affect the stable distribution.)

For the unstable distribution (sid), these problems have been fixed in version 1.2.35-1.

We recommend that you upgrade your libpng packages.");

  script_tag(name:"affected", value:"'libpng' package(s) on Debian 4, Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libpng12-0", ver:"1.2.15~beta5-1+etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpng12-0-udeb", ver:"1.2.15~beta5-1+etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpng12-dev", ver:"1.2.15~beta5-1+etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpng3", ver:"1.2.15~beta5-1+etch2", rls:"DEB4"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libpng12-0", ver:"1.2.27-2+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpng12-0-udeb", ver:"1.2.27-2+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpng12-dev", ver:"1.2.27-2+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpng3", ver:"1.2.27-2+lenny2", rls:"DEB5"))) {
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
