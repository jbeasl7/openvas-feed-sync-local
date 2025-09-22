# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6588.2");
  script_cve_id("CVE-2024-22365");
  script_tag(name:"creation_date", value:"2024-03-27 04:09:51 +0000 (Wed, 27 Mar 2024)");
  script_version("2024-03-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-03-27 05:05:31 +0000 (Wed, 27 Mar 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-14 00:27:40 +0000 (Wed, 14 Feb 2024)");

  script_name("Ubuntu: Security Advisory (USN-6588-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6588-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6588-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pam' package(s) announced via the USN-6588-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6588-1 fixed a vulnerability in PAM. This update
provides the corresponding updates for Ubuntu 14.04 LTS,
Ubuntu 16.04 LTS, and Ubuntu 18.04 LTS.

Original advisory details:

 Matthias Gerstner discovered that the PAM pam_namespace module incorrectly
 handled special files when performing directory checks. A local attacker
 could possibly use this issue to cause PAM to stop responding, resulting in
 a denial of service.");

  script_tag(name:"affected", value:"'pam' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libpam-modules", ver:"1.1.8-1ubuntu2.2+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libpam-modules", ver:"1.1.8-3.2ubuntu2.3+esm5", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libpam-modules", ver:"1.1.8-3.6ubuntu2.18.04.6+esm1", rls:"UBUNTU18.04 LTS"))) {
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
