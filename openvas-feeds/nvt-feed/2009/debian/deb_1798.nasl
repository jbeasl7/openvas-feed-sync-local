# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63963");
  script_cve_id("CVE-2009-1194");
  script_tag(name:"creation_date", value:"2009-05-11 18:24:31 +0000 (Mon, 11 May 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1798-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1798-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1798-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1798");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pango1.0' package(s) announced via the DSA-1798-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Will Drewry discovered that pango, a system for layout and rendering of internationalized text, is prone to an integer overflow via long glyphstrings. This could cause the execution of arbitrary code when displaying crafted data through an application using the pango library.

For the oldstable distribution (etch), this problem has been fixed in version 1.14.8-5+etch1.

For the stable distribution (lenny), this problem has been fixed in version 1.20.5-3+lenny1.

For the testing distribution (squeeze) and the unstable distribution (sid), this problem has been fixed in version 1.24-1.

We recommend that you upgrade your pango1.0 packages.");

  script_tag(name:"affected", value:"'pango1.0' package(s) on Debian 4, Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libpango1.0-0", ver:"1.14.8-5+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpango1.0-0-dbg", ver:"1.14.8-5+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpango1.0-common", ver:"1.14.8-5+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpango1.0-dev", ver:"1.14.8-5+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpango1.0-doc", ver:"1.14.8-5+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpango1.0-udeb", ver:"1.14.8-5+etch1", rls:"DEB4"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libpango1.0-0", ver:"1.20.5-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpango1.0-0-dbg", ver:"1.20.5-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpango1.0-common", ver:"1.20.5-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpango1.0-dev", ver:"1.20.5-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpango1.0-doc", ver:"1.20.5-3+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpango1.0-udeb", ver:"1.20.5-3+lenny1", rls:"DEB5"))) {
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
