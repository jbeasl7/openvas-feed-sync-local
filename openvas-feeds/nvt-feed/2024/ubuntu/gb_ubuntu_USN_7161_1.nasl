# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7161.1");
  script_cve_id("CVE-2024-29018", "CVE-2024-41110");
  script_tag(name:"creation_date", value:"2024-12-17 04:08:31 +0000 (Tue, 17 Dec 2024)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-09 15:40:20 +0000 (Wed, 09 Apr 2025)");

  script_name("Ubuntu: Security Advisory (USN-7161-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|24\.04\ LTS|24\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7161-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7161-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker.io, docker.io-app' package(s) announced via the USN-7161-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Yair Zak discovered that Docker could unexpectedly forward DNS requests
from internal networks in an unexpected manner. An attacker could possibly
use this issue to exfiltrate data by encoding information in DNS queries
to controlled nameservers. This issue was only addressed for the source package
docker.io-app in Ubuntu 24.04 LTS. (CVE-2024-29018)

Cory Snider discovered that Docker did not properly handle authorization
plugin request processing. An attacker could possibly use this issue to
bypass authorization controls by forwarding API requests without their
full body, leading to unauthorized actions. This issue was only addressed for
the source package docker.io-app in Ubuntu 24.10 and Ubuntu 24.04 LTS,
and the source package docker.io in Ubuntu 18.04 LTS. (CVE-2024-41110)");

  script_tag(name:"affected", value:"'docker.io, docker.io-app' package(s) on Ubuntu 18.04, Ubuntu 24.04, Ubuntu 24.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"docker.io", ver:"20.10.21-0ubuntu1~18.04.3+esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"docker.io", ver:"26.1.3-0ubuntu1~24.04.1+esm1", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"docker.io", ver:"26.1.3-0ubuntu1.1", rls:"UBUNTU24.10"))) {
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
