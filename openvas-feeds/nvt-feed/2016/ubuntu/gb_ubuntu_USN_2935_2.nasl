# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842696");
  script_cve_id("CVE-2013-7041", "CVE-2014-2583", "CVE-2015-3238");
  script_tag(name:"creation_date", value:"2016-03-17 04:11:12 +0000 (Thu, 17 Mar 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-08-25 15:08:09 +0000 (Tue, 25 Aug 2015)");

  script_name("Ubuntu: Security Advisory (USN-2935-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|15\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2935-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2935-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1558114");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pam' package(s) announced via the USN-2935-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2935-1 fixed vulnerabilities in PAM. The updates contained a packaging
change that prevented upgrades in certain multiarch environments. This
update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that the PAM pam_userdb module incorrectly used a
 case-insensitive method when comparing hashed passwords. A local attacker
 could possibly use this issue to make brute force attacks easier. This
 issue only affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2013-7041)

 Sebastian Krahmer discovered that the PAM pam_timestamp module incorrectly
 performed filtering. A local attacker could use this issue to create
 arbitrary files, or possibly bypass authentication. This issue only
 affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2014-2583)

 Sebastien Macke discovered that the PAM pam_unix module incorrectly handled
 large passwords. A local attacker could possibly use this issue in certain
 environments to enumerate usernames or cause a denial of service.
 (CVE-2015-3238)");

  script_tag(name:"affected", value:"'pam' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libpam-modules", ver:"1.1.3-7ubuntu2.2", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libpam-modules", ver:"1.1.8-1ubuntu2.2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU15.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libpam-modules", ver:"1.1.8-3.1ubuntu3.2", rls:"UBUNTU15.10"))) {
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
