# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57205");
  script_cve_id("CVE-2006-3459", "CVE-2006-3460", "CVE-2006-3461", "CVE-2006-3462", "CVE-2006-3463", "CVE-2006-3464", "CVE-2006-3465");
  script_tag(name:"creation_date", value:"2008-01-17 22:13:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1137-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1137-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/DSA-1137-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1137");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tiff' package(s) announced via the DSA-1137-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tavis Ormandy of the Google Security Team discovered several problems in the TIFF library. The Common Vulnerabilities and Exposures project identifies the following issues:

CVE-2006-3459

Several stack-buffer overflows have been discovered.

CVE-2006-3460

A heap overflow vulnerability in the JPEG decoder may overrun a buffer with more data than expected.

CVE-2006-3461

A heap overflow vulnerability in the PixarLog decoder may allow an attacker to execute arbitrary code.

CVE-2006-3462

A heap overflow vulnerability has been discovered in the NeXT RLE decoder.

CVE-2006-3463

An loop was discovered where a 16bit unsigned short was used to iterate over a 32bit unsigned value so that the loop would never terminate and continue forever.

CVE-2006-3464

Multiple unchecked arithmetic operations were uncovered, including a number of the range checking operations designed to ensure the offsets specified in TIFF directories are legitimate.

CVE-2006-3465

A flaw was also uncovered in libtiffs custom tag support which may result in abnormal behaviour, crashes, or potentially arbitrary code execution.

For the stable distribution (sarge) these problems have been fixed in version 3.7.2-7.

For the unstable distribution (sid) these problems have been fixed in version 3.8.2-6.

We recommend that you upgrade your libtiff packages.");

  script_tag(name:"affected", value:"'tiff' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-opengl", ver:"3.7.2-7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-tools", ver:"3.7.2-7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff4", ver:"3.7.2-7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff4-dev", ver:"3.7.2-7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiffxx0", ver:"3.7.2-7", rls:"DEB3.1"))) {
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
