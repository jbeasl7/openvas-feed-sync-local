# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6735.1");
  script_cve_id("CVE-2023-30588", "CVE-2023-30589", "CVE-2023-30590");
  script_tag(name:"creation_date", value:"2024-04-17 04:10:18 +0000 (Wed, 17 Apr 2024)");
  script_version("2024-04-18T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-04-18 05:05:33 +0000 (Thu, 18 Apr 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-04 17:39:07 +0000 (Mon, 04 Dec 2023)");

  script_name("Ubuntu: Security Advisory (USN-6735-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6735-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6735-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs' package(s) announced via the USN-6735-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Node.js incorrectly handled the use of invalid public
keys while creating an x509 certificate. If a user or an automated system were
tricked into opening a specially crafted input file, a remote attacker could
possibly use this issue to cause a denial of service. This issue only affected
Ubuntu 23.10. (CVE-2023-30588)

It was discovered that Node.js incorrectly handled the use of CRLF sequences to
delimit HTTP requests. If a user or an automated system were tricked into
opening a specially crafted input file, a remote attacker could possibly use
this issue to obtain unauthorised access. This issue only affected
Ubuntu 23.10. (CVE-2023-30589)

It was discovered that Node.js incorrectly described the generateKeys()
function in the documentation. This inconsistency could possibly lead to
security issues in applications that use these APIs.
(CVE-2023-30590)");

  script_tag(name:"affected", value:"'nodejs' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"nodejs", ver:"0.10.25~dfsg2-2ubuntu1.2+esm2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs-dev", ver:"0.10.25~dfsg2-2ubuntu1.2+esm2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs-legacy", ver:"0.10.25~dfsg2-2ubuntu1.2+esm2", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"nodejs", ver:"4.2.6~dfsg-1ubuntu4.2+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs-dev", ver:"4.2.6~dfsg-1ubuntu4.2+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs-legacy", ver:"4.2.6~dfsg-1ubuntu4.2+esm3", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"nodejs", ver:"8.10.0~dfsg-2ubuntu0.4+esm5", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs-dev", ver:"8.10.0~dfsg-2ubuntu0.4+esm5", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs-doc", ver:"8.10.0~dfsg-2ubuntu0.4+esm5", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libnode-dev", ver:"10.19.0~dfsg-3ubuntu1.6", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnode64", ver:"10.19.0~dfsg-3ubuntu1.6", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs", ver:"10.19.0~dfsg-3ubuntu1.6", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs-doc", ver:"10.19.0~dfsg-3ubuntu1.6", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libnode-dev", ver:"12.22.9~dfsg-1ubuntu3.5", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnode72", ver:"12.22.9~dfsg-1ubuntu3.5", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs", ver:"12.22.9~dfsg-1ubuntu3.5", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs-doc", ver:"12.22.9~dfsg-1ubuntu3.5", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libnode-dev", ver:"18.13.0+dfsg1-1ubuntu2.2", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnode108", ver:"18.13.0+dfsg1-1ubuntu2.2", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs", ver:"18.13.0+dfsg1-1ubuntu2.2", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs-doc", ver:"18.13.0+dfsg1-1ubuntu2.2", rls:"UBUNTU23.10"))) {
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
