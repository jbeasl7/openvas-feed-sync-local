# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7586.1");
  script_cve_id("CVE-2024-34702", "CVE-2024-34703", "CVE-2024-39312", "CVE-2024-50382", "CVE-2024-50383");
  script_tag(name:"creation_date", value:"2025-06-24 04:10:04 +0000 (Tue, 24 Jun 2025)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-05 15:02:51 +0000 (Wed, 05 Mar 2025)");

  script_name("Ubuntu: Security Advisory (USN-7586-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS|24\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7586-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7586-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'botan' package(s) announced via the USN-7586-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Botan could have compiler dependent operations
induced under certain circumstances. An attacker could possibly use this
issue to cause undefined behavior. (CVE-2024-50382, CVE-2024-50383)

Bing Shi discovered that Botan did not limit the size of certain inputs
when checking primality and name constraints. An attacker could possibly
use this issue to cause a denial of service. (CVE-2024-34702,
CVE-2024-34703)

It was discovered that Botan did not correctly handle conflicting name
constraints. An attacker could possibly use this issue to bypass
authentication. (CVE-2024-39312)");

  script_tag(name:"affected", value:"'botan' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 24.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"botan", ver:"2.19.1+dfsg-2ubuntu1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbotan-2-19", ver:"2.19.1+dfsg-2ubuntu1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbotan-2-dev", ver:"2.19.1+dfsg-2ubuntu1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-botan", ver:"2.19.1+dfsg-2ubuntu1+esm1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"botan", ver:"2.19.3+dfsg-1ubuntu2+esm1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbotan-2-19", ver:"2.19.3+dfsg-1ubuntu2+esm1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbotan-2-dev", ver:"2.19.3+dfsg-1ubuntu2+esm1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-botan", ver:"2.19.3+dfsg-1ubuntu2+esm1", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"botan", ver:"2.19.3+dfsg-1ubuntu2.1", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbotan-2-19", ver:"2.19.3+dfsg-1ubuntu2.1", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbotan-2-dev", ver:"2.19.3+dfsg-1ubuntu2.1", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-botan", ver:"2.19.3+dfsg-1ubuntu2.1", rls:"UBUNTU24.10"))) {
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
