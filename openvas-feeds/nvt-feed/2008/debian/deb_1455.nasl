# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60110");
  script_cve_id("CVE-2007-3641", "CVE-2007-3644", "CVE-2007-3645");
  script_tag(name:"creation_date", value:"2008-01-17 22:23:47 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1455-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1455-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1455-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1455");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libarchive' package(s) announced via the DSA-1455-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local/remote vulnerabilities have been discovered in libarchive1, a single library to read/write tar, cpio, pax, zip, iso9660 archives. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-3641

It was discovered that libarchive1 would miscompute the length of a buffer resulting in a buffer overflow if yet another type of corruption occurred in a pax extension header.

CVE-2007-3644

It was discovered that if an archive prematurely ended within a pax extension header the libarchive1 library could enter an infinite loop.

CVE-2007-3645

If an archive prematurely ended within a tar header, immediately following a pax extension header, libarchive1 could dereference a NULL pointer.

The old stable distribution (sarge), does not contain this package.

For the stable distribution (etch), these problems have been fixed in version 1.2.53-2etch1.

For the unstable distribution (sid), these problems have been fixed in version 2.2.4-1.

We recommend that you upgrade your libarchive package.");

  script_tag(name:"affected", value:"'libarchive' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"bsdtar", ver:"1.2.53-2etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libarchive-dev", ver:"1.2.53-2etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libarchive1", ver:"1.2.53-2etch1", rls:"DEB4"))) {
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
