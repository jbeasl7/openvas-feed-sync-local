# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702915");
  script_cve_id("CVE-2014-0471", "CVE-2014-3127", "CVE-2014-3227");
  script_tag(name:"creation_date", value:"2014-04-27 22:00:00 +0000 (Sun, 27 Apr 2014)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2915-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");

  script_xref(name:"Advisory-ID", value:"DSA-2915-2");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-2915-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2915");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dpkg' package(s) announced via the DSA-2915-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jakub Wilk discovered that dpkg did not correctly parse C-style filename quoting, allowing for paths to be traversed when unpacking a source package - leading to the creation of files outside the directory of the source being unpacked.

The update to the stable distribution (wheezy) incorporates non-security changes that were targeted for the point release 7.5.

For the oldstable distribution (squeeze), this problem has been fixed in version 1.15.9.

For the stable distribution (wheezy), this problem has been fixed in version 1.16.13.

For the testing distribution (jessie), this problem will be fixed soon.

For the unstable distribution (sid), this problem will be fixed in version 1.17.8.

We recommend that you upgrade your dpkg packages.");

  script_tag(name:"affected", value:"'dpkg' package(s) on Debian 6, Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"dpkg", ver:"1.15.10", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dpkg-dev", ver:"1.15.10", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dselect", ver:"1.15.10", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdpkg-dev", ver:"1.15.10", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdpkg-perl", ver:"1.15.10", rls:"DEB6"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"dpkg", ver:"1.16.14", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dpkg-dev", ver:"1.16.14", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dselect", ver:"1.16.14", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdpkg-dev", ver:"1.16.14", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdpkg-perl", ver:"1.16.14", rls:"DEB7"))) {
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
