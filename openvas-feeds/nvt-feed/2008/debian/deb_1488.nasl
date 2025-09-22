# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60361");
  script_cve_id("CVE-2006-4758", "CVE-2006-6508", "CVE-2006-6839", "CVE-2006-6840", "CVE-2006-6841", "CVE-2008-0471");
  script_tag(name:"creation_date", value:"2008-02-15 22:29:21 +0000 (Fri, 15 Feb 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1488-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.1|4)");

  script_xref(name:"Advisory-ID", value:"DSA-1488-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1488-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1488");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'phpbb2' package(s) announced via the DSA-1488-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in phpBB, a web based bulletin board. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-0471

Private messaging allowed cross site request forgery, making it possible to delete all private messages of a user by sending them to a crafted web page.

CVE-2006-6841 / CVE-2006-6508 Cross site request forgery enabled an attacker to perform various actions on behalf of a logged in user. (Applies to sarge only.)

CVE-2006-6840

A negative start parameter could allow an attacker to create invalid output. (Applies to sarge only.)

CVE-2006-6839

Redirection targets were not fully checked, leaving room for unauthorised external redirections via a phpBB forum. (Applies to sarge only.)

CVE-2006-4758

An authenticated forum administrator may upload files of any type by using specially crafted filenames. (Applies to sarge only.)

For the old stable distribution (sarge), these problems have been fixed in version 2.0.13+1-6sarge4.

For the stable distribution (etch), these problems have been fixed in version 2.0.21-7.

For the unstable distribution (sid) these problems have been fixed in version 2.0.22-3.

We recommend that you upgrade your phpbb2 package.");

  script_tag(name:"affected", value:"'phpbb2' package(s) on Debian 3.1, Debian 4.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"phpbb2", ver:"2.0.13-6sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpbb2-conf-mysql", ver:"2.0.13-6sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpbb2-languages", ver:"2.0.13-6sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"phpbb2", ver:"2.0.21-7", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpbb2-conf-mysql", ver:"2.0.21-7", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpbb2-languages", ver:"2.0.21-7", rls:"DEB4"))) {
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
