# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.72443");
  script_cve_id("CVE-2010-2482", "CVE-2010-2595", "CVE-2010-2597", "CVE-2010-2630", "CVE-2010-4665", "CVE-2012-2088", "CVE-2012-2113", "CVE-2012-3401");
  script_tag(name:"creation_date", value:"2012-10-03 15:10:30 +0000 (Wed, 03 Oct 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2552-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2552-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/DSA-2552-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2552");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tiff' package(s) announced via the DSA-2552-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in TIFF, a library set and tools to support the Tag Image File Format (TIFF), allowing denial of service and potential privilege escalation.

These vulnerabilities can be exploited via a specially crafted TIFF image.

CVE-2012-2113

The tiff2pdf utility has an integer overflow error when parsing images.

CVE-2012-3401

Huzaifa Sidhpurwala discovered heap-based buffer overflow in the t2p_read_tiff_init() function.

CVE-2010-2482

An invalid td_stripbytecount field is not properly handle and can trigger a NULL pointer dereference.

CVE-2010-2595

An array index error, related to downsampled OJPEG input in the TIFFYCbCrtoRGB function causes an unexpected crash.

CVE-2010-2597

Also related to downsampled OJPEG input, the TIFFVStripSize function crash unexpectedly.

CVE-2010-2630

The TIFFReadDirectory function does not properly validate the data types of codec-specific tags that have an out-of-order position in a TIFF file.

CVE-2010-4665

The tiffdump utility has an integer overflow in the ReadDirectory function.

For the stable distribution (squeeze), these problems have been fixed in version 3.9.4-5+squeeze5.

For the testing distribution (wheezy), these problems have been fixed in version 4.0.2-2.

For the unstable distribution (sid), these problems have been fixed in version 4.0.2-2.

We recommend that you upgrade your tiff packages.");

  script_tag(name:"affected", value:"'tiff' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-doc", ver:"3.9.4-5+squeeze5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-opengl", ver:"3.9.4-5+squeeze5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-tools", ver:"3.9.4-5+squeeze5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff4", ver:"3.9.4-5+squeeze5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff4-dev", ver:"3.9.4-5+squeeze5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiffxx0c2", ver:"3.9.4-5+squeeze5", rls:"DEB6"))) {
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
