# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.890693");
  script_cve_id("CVE-2014-8128", "CVE-2015-7554", "CVE-2015-8668", "CVE-2016-3186", "CVE-2016-3619", "CVE-2016-3620", "CVE-2016-3621", "CVE-2016-3631", "CVE-2016-3632", "CVE-2016-3633", "CVE-2016-3634", "CVE-2016-5102", "CVE-2016-5318", "CVE-2016-5319", "CVE-2016-5652", "CVE-2016-6223", "CVE-2016-8331");
  script_tag(name:"creation_date", value:"2018-01-04 23:00:00 +0000 (Thu, 04 Jan 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-01-13 16:19:10 +0000 (Wed, 13 Jan 2016)");

  script_name("Debian: Security Advisory (DLA-693-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-693-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/DLA-693-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tiff' package(s) announced via the DLA-693-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The libtiff library and associated tools provided in libtiff-tools are vulnerable to many security problems.

This update drops many tools which are no longer supported upstream and which are affected by multiple memory corruption issues:

bmp2tiff (CVE-2016-3619, CVE-2016-3620, CVE-2016-3621, CVE-2016-5319, CVE-2015-8668)

gif2tiff (CVE-2016-3186, CVE-2016-5102)

ras2tiff

sgi2tiff

sgisv

ycbcr

rgb2ycbcr (CVE-2016-3623, CVE-2016-3624)

thumbnail (CVE-2016-3631, CVE-2016-3632, CVE-2016-3633, CVE-2016-3634, CVE-2016-8331)

This update also fixes the following issues:

CVE-2014-8128 / CVE-2015-7554, CVE-2016-5318 Multiple buffer overflows triggered through TIFFGetField() on unknown tags. Lacking an upstream fix, the list of known tags has been extended to cover all those that are in use by the TIFF tools.

CVE-2016-5652

Heap based buffer overflow in tiff2pdf.

CVE-2016-6223

Information leak in libtiff/tif_read.c. Fix out-of-bounds read on memory-mapped files in TIFFReadRawStrip1() and TIFFReadRawTile1() when stripoffset is beyond tmsize_t max value (reported by Mathias Svensson).

For Debian 7 Wheezy, these problems have been fixed in version 4.0.2-6+deb7u7.

We recommend that you upgrade your tiff packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'tiff' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-doc", ver:"4.0.2-6+deb7u7", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-opengl", ver:"4.0.2-6+deb7u7", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-tools", ver:"4.0.2-6+deb7u7", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff5", ver:"4.0.2-6+deb7u7", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff5-alt-dev", ver:"4.0.2-6+deb7u7", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff5-dev", ver:"4.0.2-6+deb7u7", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiffxx5", ver:"4.0.2-6+deb7u7", rls:"DEB7"))) {
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
