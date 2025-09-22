# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703963");
  script_cve_id("CVE-2017-1000115", "CVE-2017-1000116");
  script_tag(name:"creation_date", value:"2017-09-03 22:00:00 +0000 (Sun, 03 Sep 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-13 19:39:35 +0000 (Fri, 13 Oct 2017)");

  script_name("Debian: Security Advisory (DSA-3963-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-3963-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-3963-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3963");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mercurial' package(s) announced via the DSA-3963-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues were discovered in Mercurial, a distributed revision control system.

CVE-2017-9462 (fixed in stretch only) Jonathan Claudius of Mozilla discovered that repositories served over stdio could be tricked into granting authorized users access to the Python debugger.

CVE-2017-1000115

Mercurial's symlink auditing was incomplete, and could be abused to write files outside the repository.

CVE-2017-1000116

Joern Schneeweisz discovered that Mercurial did not correctly handle maliciously constructed ssh:// URLs. This allowed an attacker to run an arbitrary shell command.

For the oldstable distribution (jessie), these problems have been fixed in version 3.1.2-2+deb8u4.

For the stable distribution (stretch), these problems have been fixed in version 4.0-1+deb9u1.

We recommend that you upgrade your mercurial packages.");

  script_tag(name:"affected", value:"'mercurial' package(s) on Debian 8, Debian 9.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"mercurial", ver:"3.1.2-2+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mercurial-common", ver:"3.1.2-2+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"mercurial", ver:"4.0-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mercurial-common", ver:"4.0-1+deb9u1", rls:"DEB9"))) {
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
