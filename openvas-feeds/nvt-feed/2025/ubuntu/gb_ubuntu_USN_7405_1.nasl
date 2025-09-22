# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7405.1");
  script_cve_id("CVE-2016-7142", "CVE-2019-20917", "CVE-2020-25269");
  script_tag(name:"creation_date", value:"2025-04-03 04:04:10 +0000 (Thu, 03 Apr 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-15 14:33:23 +0000 (Tue, 15 Sep 2020)");

  script_name("Ubuntu: Security Advisory (USN-7405-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7405-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7405-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'inspircd' package(s) announced via the USN-7405-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that InspIRCd did not correctly handle certificate
fingerprints, which could lead to spoofing. A remote attacker could
possibly use this issue to bypass authentication. This issue only affected
Ubuntu 16.04 LTS. (CVE-2016-7142)

It was discovered that InspIRCd did not correctly handle certain memory
operations, which could lead to a NULL pointer dereference. A remote
attacker could possibly use this issue to cause a denial of service. This
issue only affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS.
(CVE-2019-20917)

It was discovered that InspIRCd did not correctly handle certain memory
operations, which could lead to a use-after-free. A remote attacker could
possibly use this issue to cause a denial of service. (CVE-2020-25269)");

  script_tag(name:"affected", value:"'inspircd' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"inspircd", ver:"2.0.20-5ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"inspircd", ver:"2.0.24-1ubuntu1+esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"inspircd", ver:"3.4.0-2ubuntu1+esm1", rls:"UBUNTU20.04 LTS"))) {
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
