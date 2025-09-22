# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7161.3");
  script_cve_id("CVE-2024-41110");
  script_tag(name:"creation_date", value:"2025-04-16 04:04:10 +0000 (Wed, 16 Apr 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7161-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|24\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7161-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7161-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker.io' package(s) announced via the USN-7161-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-7161-1 and USN-7161-2 fixed CVE-2024-41110 for source package
docker.io in Ubuntu 18.04 LTS and for source package docker.io-app in
Ubuntu 20.04 LTS, Ubuntu 22.04 LTS, Ubuntu 24.04 LTS, and Ubuntu 24.10.
This update fixes it for source package docker.io in Ubuntu 20.04 LTS,
Ubuntu 22.04 LTS, Ubuntu 24.04 LTS, and Ubuntu 24.10. These updates only
address the docker library and not the docker.io application itself, which
was already patched in the previous USNs (USN-7161-1 and USN-7161-2).

Original advisory details:

 Yair Zak discovered that Docker could unexpectedly forward DNS requests
 from internal networks in an unexpected manner. An attacker could possibly
 use this issue to exfiltrate data by encoding information in DNS queries
 to controlled nameservers. This issue was only addressed for the source
 package docker.io-app in Ubuntu 24.04 LTS. (CVE-2024-29018)

 Cory Snider discovered that Docker did not properly handle authorization
 plugin request processing. An attacker could possibly use this issue to
 bypass authorization controls by forwarding API requests without their
 full body, leading to unauthorized actions. This issue was only addressed
 for the source package docker.io-app in Ubuntu 24.10 and
 Ubuntu 24.04 LTS, and the source package docker.io in Ubuntu 18.04 LTS.
 (CVE-2024-41110)");

  script_tag(name:"affected", value:"'docker.io' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 24.10.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"golang-github-docker-docker-dev", ver:"20.10.21-0ubuntu1~20.04.6+esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"golang-github-docker-docker-dev", ver:"20.10.21-0ubuntu1~22.04.7+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"golang-github-docker-docker-dev", ver:"20.10.25+dfsg1-2ubuntu1+esm1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.10") {

  if(!isnull(res = isdpkgvuln(pkg:"golang-github-docker-docker-dev", ver:"26.1.4+dfsg2-1ubuntu1.1", rls:"UBUNTU24.10"))) {
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
