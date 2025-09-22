# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703218");
  script_cve_id("CVE-2015-0844");
  script_tag(name:"creation_date", value:"2015-04-09 22:00:00 +0000 (Thu, 09 Apr 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-3218-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3218-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3218-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3218");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wesnoth-1.10' package(s) announced via the DSA-3218-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ignacio R. Morelle discovered that missing path restrictions in the Battle of Wesnoth game could result in the disclosure of arbitrary files in the user's home directory if malicious campaigns/maps are loaded.

For the stable distribution (wheezy), this problem has been fixed in version 1.10.3-3+deb7u1.

For the unstable distribution (sid), this problem has been fixed in version 1:1.10.7-2 and in version 1:1.12.1-1 of the wesnoth-1.12 source package.

We recommend that you upgrade your wesnoth-1.10 packages.");

  script_tag(name:"affected", value:"'wesnoth-1.10' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"wesnoth", ver:"1:1.10.3-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wesnoth-1.10", ver:"1:1.10.3-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wesnoth-1.10-aoi", ver:"1:1.10.3-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wesnoth-1.10-core", ver:"1:1.10.3-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wesnoth-1.10-data", ver:"1:1.10.3-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wesnoth-1.10-dbg", ver:"1:1.10.3-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wesnoth-1.10-did", ver:"1:1.10.3-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wesnoth-1.10-dm", ver:"1:1.10.3-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wesnoth-1.10-dw", ver:"1:1.10.3-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wesnoth-1.10-ei", ver:"1:1.10.3-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wesnoth-1.10-httt", ver:"1:1.10.3-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wesnoth-1.10-l", ver:"1:1.10.3-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wesnoth-1.10-low", ver:"1:1.10.3-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wesnoth-1.10-music", ver:"1:1.10.3-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wesnoth-1.10-nr", ver:"1:1.10.3-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wesnoth-1.10-server", ver:"1:1.10.3-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wesnoth-1.10-sof", ver:"1:1.10.3-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wesnoth-1.10-sotbe", ver:"1:1.10.3-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wesnoth-1.10-thot", ver:"1:1.10.3-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wesnoth-1.10-tools", ver:"1:1.10.3-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wesnoth-1.10-trow", ver:"1:1.10.3-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wesnoth-1.10-tsg", ver:"1:1.10.3-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wesnoth-1.10-ttb", ver:"1:1.10.3-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wesnoth-1.10-utbs", ver:"1:1.10.3-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wesnoth-core", ver:"1:1.10.3-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wesnoth-music", ver:"1:1.10.3-3+deb7u1", rls:"DEB7"))) {
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
