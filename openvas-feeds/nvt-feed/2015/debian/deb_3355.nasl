# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703355");
  script_cve_id("CVE-2015-5198", "CVE-2015-5199", "CVE-2015-5200");
  script_tag(name:"creation_date", value:"2015-09-09 22:00:00 +0000 (Wed, 09 Sep 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3355-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3355-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3355-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3355");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libvdpau' package(s) announced via the DSA-3355-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Florian Weimer of Red Hat Product Security discovered that libvdpau, the VDPAU wrapper library, did not properly validate environment variables, allowing local attackers to gain additional privileges.

For the oldstable distribution (wheezy), these problems have been fixed in version 0.4.1-7+deb7u1.

For the stable distribution (jessie), these problems have been fixed in version 0.8-3+deb8u1.

For the testing distribution (stretch), these problems have been fixed in version 1.1.1-1.

For the unstable distribution (sid), these problems have been fixed in version 1.1.1-1.

We recommend that you upgrade your libvdpau packages.");

  script_tag(name:"affected", value:"'libvdpau' package(s) on Debian 7, Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libvdpau-dev", ver:"0.4.1-7+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvdpau-doc", ver:"0.4.1-7+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvdpau1", ver:"0.4.1-7+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"libvdpau-dev", ver:"0.8-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvdpau-doc", ver:"0.8-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvdpau1", ver:"0.8-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvdpau1-dbg", ver:"0.8-3+deb8u1", rls:"DEB8"))) {
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
