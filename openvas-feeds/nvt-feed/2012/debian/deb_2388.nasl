# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70707");
  script_cve_id("CVE-2010-2642", "CVE-2011-0433", "CVE-2011-0764", "CVE-2011-1552", "CVE-2011-1553", "CVE-2011-1554");
  script_tag(name:"creation_date", value:"2012-02-11 08:27:53 +0000 (Sat, 11 Feb 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2388-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");

  script_xref(name:"Advisory-ID", value:"DSA-2388-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/DSA-2388-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2388");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 't1lib' package(s) announced via the DSA-2388-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in t1lib, a Postscript Type 1 font rasterizer library, some of which might lead to code execution through the opening of files embedding bad fonts.

CVE-2010-2642

A heap-based buffer overflow in the AFM font metrics parser potentially leads to the execution of arbitrary code.

CVE-2011-0433

Another heap-based buffer overflow in the AFM font metrics parser potentially leads to the execution of arbitrary code.

CVE-2011-0764

An invalid pointer dereference allows execution of arbitrary code using crafted Type 1 fonts.

CVE-2011-1552

Another invalid pointer dereference results in an application crash, triggered by crafted Type 1 fonts.

CVE-2011-1553

A use-after-free vulnerability results in an application crash, triggered by crafted Type 1 fonts.

CVE-2011-1554

An off-by-one error results in an invalid memory read and application crash, triggered by crafted Type 1 fonts.

For the oldstable distribution (lenny), this problem has been fixed in version 5.1.2-3+lenny1.

For the stable distribution (squeeze), this problem has been fixed in version 5.1.2-3+squeeze1.

For the testing distribution (wheezy), this problem has been fixed in version 5.1.2-3.4.

For the unstable distribution (sid), this problem has been fixed in version 5.1.2-3.4.

We recommend that you upgrade your t1lib packages.");

  script_tag(name:"affected", value:"'t1lib' package(s) on Debian 5, Debian 6.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"libt1-5", ver:"5.1.2-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libt1-5-dbg", ver:"5.1.2-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libt1-dev", ver:"5.1.2-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libt1-doc", ver:"5.1.2-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"t1lib-bin", ver:"5.1.2-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"libt1-5", ver:"5.1.2-3+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libt1-5-dbg", ver:"5.1.2-3+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libt1-dev", ver:"5.1.2-3+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libt1-doc", ver:"5.1.2-3+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"t1lib-bin", ver:"5.1.2-3+squeeze1", rls:"DEB6"))) {
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
