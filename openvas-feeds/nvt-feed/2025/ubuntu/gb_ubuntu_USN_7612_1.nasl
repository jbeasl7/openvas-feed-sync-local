# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7612.1");
  script_cve_id("CVE-2024-1681", "CVE-2024-6221", "CVE-2024-6839", "CVE-2024-6844", "CVE-2024-6866");
  script_tag(name:"creation_date", value:"2025-07-04 04:09:47 +0000 (Fri, 04 Jul 2025)");
  script_version("2025-08-01T05:45:36+0000");
  script_tag(name:"last_modification", value:"2025-08-01 05:45:36 +0000 (Fri, 01 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-01 01:36:17 +0000 (Fri, 01 Aug 2025)");

  script_name("Ubuntu: Security Advisory (USN-7612-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|24\.10|25\.04)");

  script_xref(name:"Advisory-ID", value:"USN-7612-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7612-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-flask-cors' package(s) announced via the USN-7612-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Flask-CORS did not correctly handle certain regular
expressions. A remote attacker could possibly use this issue to leak
sensitive information or bypass authentication mechanisms. (CVE-2024-6839)
It was discovered that Flask-CORS allowed certain CORS headers to be
enabled by default. A remote attacker could possibly use this issue to leak
sensitive information. This issue only affected Ubuntu 20.04 LTS, Ubuntu
22.04 LTS, Ubuntu 24.04 LTS and Ubuntu 24.10. (CVE-2024-6221) It was
discovered that Flask-CORS did not correctly handle case sensitivity when
matching paths. A remote attacker could possibly use this issue to leak
sensitive information. (CVE-2024-6866) It was discovered that Flask-CORS
did not correctly handle certain characters in URL paths. A remote attacker
could possibly use this issue to leak sensitive information or bypass
authentication mechanisms. (CVE-2024-6844) Elias Hohl was discovered that
Flask-CORS did not correctly sanitize log entries. A remote attacker could
possibly use this issue to corrupt log files. This issue only affected
Ubuntu 20.04 LTS, Ubuntu 22.04 LTS and Ubuntu 24.04 LTS. (CVE-2024-1681)");

  script_tag(name:"affected", value:"'python-flask-cors' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 24.10, Ubuntu 25.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python3-flask-cors", ver:"3.0.8-2ubuntu0.1+esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3-flask-cors", ver:"3.0.9-2ubuntu0.1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3-flask-cors", ver:"4.0.0-1ubuntu0.1~esm1", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3-flask-cors", ver:"4.0.1-1ubuntu0.1", rls:"UBUNTU24.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3-flask-cors", ver:"5.0.0-1ubuntu0.1", rls:"UBUNTU25.04"))) {
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
