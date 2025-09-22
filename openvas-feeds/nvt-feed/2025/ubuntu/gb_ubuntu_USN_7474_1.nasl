# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7474.1");
  script_cve_id("CVE-2023-28840", "CVE-2023-28841", "CVE-2023-28842", "CVE-2024-23651", "CVE-2024-23652", "CVE-2024-36621", "CVE-2024-36623");
  script_tag(name:"creation_date", value:"2025-05-02 04:04:40 +0000 (Fri, 02 May 2025)");
  script_version("2025-05-02T05:40:07+0000");
  script_tag(name:"last_modification", value:"2025-05-02 05:40:07 +0000 (Fri, 02 May 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-09 01:44:27 +0000 (Fri, 09 Feb 2024)");

  script_name("Ubuntu: Security Advisory (USN-7474-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7474-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7474-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker.io' package(s) announced via the USN-7474-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cory Snider discovered that Docker incorrectly handled networking packet
encapsulation. An attacker could use this issue to inject internet
packets in established connection, possibly causing a denial of service or
bypassing firewall protections. This issue only affected Ubuntu 22.04 LTS,
Ubuntu 20.04 LTS, and Ubuntu 18.04 LTS. (CVE-2023-28840, CVE-2023-28841,
CVE-2023-28842)

Rory McNamara discovered that Docker incorrectly handled cache in the
BuildKit toolkit. An attacker could possibly use this issue to expose
sensitive information. (CVE-2024-23651)

It was discovered that Docker incorrectly handled parallel operations in
some circumstances, which could possibly lead to undefined behavior.
(CVE-2024-36621, CVE-2024-36623)

Rory McNamara discovered that Docker incorrectly verified file paths during
a certain command in the BuildKit toolkit. An attacker could possibly use
this issue to delete arbitrary files from the system. (CVE-2024-23652)");

  script_tag(name:"affected", value:"'docker.io' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"docker.io", ver:"20.10.21-0ubuntu1~18.04.3+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-github-docker-docker-dev", ver:"20.10.21-0ubuntu1~18.04.3+esm3", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"golang-github-docker-docker-dev", ver:"20.10.21-0ubuntu1~20.04.6+esm2", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"golang-github-docker-docker-dev", ver:"20.10.21-0ubuntu1~22.04.7+esm2", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"golang-github-docker-docker-dev", ver:"20.10.25+dfsg1-2ubuntu1+esm2", rls:"UBUNTU24.04 LTS"))) {
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
