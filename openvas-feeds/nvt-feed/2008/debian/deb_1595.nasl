# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61171");
  script_cve_id("CVE-2008-1377", "CVE-2008-1379", "CVE-2008-2360", "CVE-2008-2361", "CVE-2008-2362");
  script_tag(name:"creation_date", value:"2008-06-27 22:42:46 +0000 (Fri, 27 Jun 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1595-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1595-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1595-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1595");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xorg-server' package(s) announced via the DSA-1595-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local vulnerabilities have been discovered in the X Window system. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-1377

Lack of validation of the parameters of the SProcSecurityGenerateAuthorization and SProcRecordCreateContext functions makes it possible for a specially crafted request to trigger the swapping of bytes outside the parameter of these requests, causing memory corruption.

CVE-2008-1379

An integer overflow in the validation of the parameters of the ShmPutImage() request makes it possible to trigger the copy of arbitrary server memory to a pixmap that can subsequently be read by the client, to read arbitrary parts of the X server memory space.

CVE-2008-2360

An integer overflow may occur in the computation of the size of the glyph to be allocated by the AllocateGlyph() function which will cause less memory to be allocated than expected, leading to later heap overflow.

CVE-2008-2361

An integer overflow may occur in the computation of the size of the glyph to be allocated by the ProcRenderCreateCursor() function which will cause less memory to be allocated than expected, leading later to dereferencing un-mapped memory, causing a crash of the X server.

CVE-2008-2362

Integer overflows can also occur in the code validating the parameters for the SProcRenderCreateLinearGradient, SProcRenderCreateRadialGradient and SProcRenderCreateConicalGradient functions, leading to memory corruption by swapping bytes outside of the intended request parameters.

For the stable distribution (etch), these problems have been fixed in version 2:1.1.1-21etch5.

For the unstable distribution (sid), these problems have been fixed in version 2:1.4.1~git20080517-2.

We recommend that you upgrade your xorg-server package.");

  script_tag(name:"affected", value:"'xorg-server' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"xdmx", ver:"2:1.1.1-21etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xdmx-tools", ver:"2:1.1.1-21etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xnest", ver:"2:1.1.1-21etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xephyr", ver:"2:1.1.1-21etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"2:1.1.1-21etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-dev", ver:"2:1.1.1-21etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xvfb", ver:"2:1.1.1-21etch5", rls:"DEB4"))) {
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
