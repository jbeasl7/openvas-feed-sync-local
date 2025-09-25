# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7762.1");
  script_cve_id("CVE-2023-32681", "CVE-2023-45803", "CVE-2024-3651", "CVE-2024-47081");
  script_tag(name:"creation_date", value:"2025-09-24 04:04:23 +0000 (Wed, 24 Sep 2025)");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-11 14:58:01 +0000 (Thu, 11 Jul 2024)");

  script_name("Ubuntu: Security Advisory (USN-7762-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS|25\.04)");

  script_xref(name:"Advisory-ID", value:"USN-7762-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7762-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2031880");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-pip' package(s) announced via the USN-7762-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dennis Brinkrolf and Tobias Funke discovered that Requests incorrectly
leaked Proxy-Authorization headers. A remote attacker could possibly use
this issue to obtain sensitive information. This update addresses the issue
in the Requests module bundled into pip in Ubuntu 22.04 LTS.
(CVE-2023-32681)

It was discovered that urllib3 didn't strip HTTP body on status code
303 redirects under certain circumstances. A remote attacker could
possibly use this issue to obtain sensitive information. This update
addresses the issue in the urllib3 module bundled into pip in Ubuntu
24.04 LTS. (CVE-2023-45803)

Guido Vranken discovered that idna did not properly manage certain inputs,
which could lead to significant resource consumption. An attacker could
possibly use this issue to cause a denial of service. This update addresses
the issue in the idna module bundled into pip in Ubuntu 22.04 LTS and
Ubuntu 24.04 LTS. (CVE-2024-3651)

Juho Forsen discovered that Requests did not correctly parse URLs. A
remote attacker could possibly use this issue to leak sensitive
information. This update addresses the issue in the Requests module bundled
into pip in Ubuntu 22.04 LTS, Ubuntu 24.04 LTS, and Ubuntu 25.04.
(CVE-2024-47081)");

  script_tag(name:"affected", value:"'python-pip' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.04.");

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

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"python3-pip", ver:"22.0.2+dfsg-1ubuntu0.7", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-pip-whl", ver:"22.0.2+dfsg-1ubuntu0.7", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3-pip", ver:"24.0+dfsg-1ubuntu1.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-pip-whl", ver:"24.0+dfsg-1ubuntu1.3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.04") {

  if(!isnull(res = isdpkgvuln(pkg:"python3-pip", ver:"25.0+dfsg-1ubuntu0.2", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-pip-whl", ver:"25.0+dfsg-1ubuntu0.2", rls:"UBUNTU25.04"))) {
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
