# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7231.1");
  script_cve_id("CVE-2023-27783", "CVE-2023-27784", "CVE-2023-27785", "CVE-2023-27786", "CVE-2023-27787", "CVE-2023-27788", "CVE-2023-27789", "CVE-2023-4256", "CVE-2023-43279");
  script_tag(name:"creation_date", value:"2025-01-29 04:07:51 +0000 (Wed, 29 Jan 2025)");
  script_version("2025-01-29T05:37:24+0000");
  script_tag(name:"last_modification", value:"2025-01-29 05:37:24 +0000 (Wed, 29 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-23 17:26:57 +0000 (Thu, 23 Mar 2023)");

  script_name("Ubuntu: Security Advisory (USN-7231-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7231-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7231-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tcpreplay' package(s) announced via the USN-7231-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Tcpreplay incorrectly handled memory when using the
tcprewrite utility. A remote attacker could possibly use this issue to
cause Tcpreplay to crash, resulting in a denial of service.
(CVE-2023-27783)

It was discovered that Tcpreplay incorrectly validated external input. A
remote attacker could possibly use this issue to cause Tcpreplay to crash,
resulting in a denial of service. (CVE-2023-27784, CVE-2023-27785,
CVE-2023-27786, CVE-2023-27787, CVE-2023-27788, CVE-2023-27789)

It was discovered that Tcpreplay incorrectly handled memory when using the
tcprewrite utility. An attacker could possibly use this issue to cause
Tcpreplay to crash, resulting in a denial of service. (CVE-2023-4256,
CVE-2023-43279)");

  script_tag(name:"affected", value:"'tcpreplay' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"tcpreplay", ver:"3.4.4-2+deb8u1ubuntu0.1~esm3", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"tcpreplay", ver:"4.2.6-1ubuntu0.1~esm5", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"tcpreplay", ver:"4.3.2-1ubuntu0.1~esm3", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"tcpreplay", ver:"4.3.4-1ubuntu0.1~esm2", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"tcpreplay", ver:"4.4.4-1ubuntu0.1~esm1", rls:"UBUNTU24.04 LTS"))) {
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
