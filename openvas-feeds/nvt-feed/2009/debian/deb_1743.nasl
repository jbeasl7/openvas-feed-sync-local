# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63608");
  script_cve_id("CVE-2007-5137", "CVE-2007-5378");
  script_tag(name:"creation_date", value:"2009-03-19 23:52:38 +0000 (Thu, 19 Mar 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1743-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1743-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1743-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1743");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libtk-img' package(s) announced via the DSA-1743-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two buffer overflows have been found in the GIF image parsing code of Tk, a cross-platform graphical toolkit, which could lead to the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-5137

It was discovered that libtk-img is prone to a buffer overflow via specially crafted multi-frame interlaced GIF files.

CVE-2007-5378

It was discovered that libtk-img is prone to a buffer overflow via specially crafted GIF files with certain subimage sizes.

For the stable distribution (lenny), these problems have been fixed in version 1.3-release-7+lenny1.

For the oldstable distribution (etch), these problems have been fixed in version 1.3-15etch3.

For the testing distribution (squeeze) and the unstable distribution (sid), these problems have been fixed in version 1.3-release-8.

We recommend that you upgrade your libtk-img packages.");

  script_tag(name:"affected", value:"'libtk-img' package(s) on Debian 4, Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libtk-img", ver:"1:1.3-15etch3", rls:"DEB4"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libtk-img", ver:"1:1.3-release-7+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtk-img-dev", ver:"1:1.3-release-7+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtk-img-doc", ver:"1:1.3-release-7+lenny1", rls:"DEB5"))) {
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
