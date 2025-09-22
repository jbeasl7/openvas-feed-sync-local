# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702927");
  script_cve_id("CVE-2014-0209", "CVE-2014-0210", "CVE-2014-0211");
  script_tag(name:"creation_date", value:"2014-05-12 22:00:00 +0000 (Mon, 12 May 2014)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2927-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");

  script_xref(name:"Advisory-ID", value:"DSA-2927-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-2927-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2927");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libxfont' package(s) announced via the DSA-2927-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ilja van Sprundel of IOActive discovered several security issues in the X.Org libXfont library, which may allow a local, authenticated user to attempt to raise privileges, or a remote attacker who can control the font server to attempt to execute code with the privileges of the X server.

CVE-2014-0209

Integer overflow of allocations in font metadata file parsing could allow a local user who is already authenticated to the X server to overwrite other memory in the heap.

CVE-2014-0210

libxfont does not validate length fields when parsing xfs protocol replies allowing to write past the bounds of allocated memory when storing the returned data from the font server.

CVE-2014-0211

Integer overflows calculating memory needs for xfs replies could result in allocating too little memory and then writing the returned data from the font server past the end of the allocated buffer.

For the oldstable distribution (squeeze), these problems have been fixed in version 1:1.4.1-5.

For the stable distribution (wheezy), these problems have been fixed in version 1:1.4.5-4.

For the unstable distribution (sid), these problems have been fixed in version 1:1.4.7-2.

We recommend that you upgrade your libxfont packages.");

  script_tag(name:"affected", value:"'libxfont' package(s) on Debian 6, Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libxfont-dev", ver:"1:1.4.1-5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxfont1", ver:"1:1.4.1-5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxfont1-dbg", ver:"1:1.4.1-5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxfont1-udeb", ver:"1:1.4.1-5", rls:"DEB6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"libxfont-dev", ver:"1:1.4.5-4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxfont1", ver:"1:1.4.5-4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxfont1-dbg", ver:"1:1.4.5-4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxfont1-udeb", ver:"1:1.4.5-4", rls:"DEB7"))) {
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
