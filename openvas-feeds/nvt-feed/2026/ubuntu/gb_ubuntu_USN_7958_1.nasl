# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.7958.1");
  script_cve_id("CVE-2019-14863", "CVE-2022-25844", "CVE-2023-26116", "CVE-2023-26117", "CVE-2023-26118", "CVE-2024-21490", "CVE-2024-8372", "CVE-2024-8373", "CVE-2025-0716", "CVE-2025-2336");
  script_tag(name:"creation_date", value:"2026-01-15 04:19:36 +0000 (Thu, 15 Jan 2026)");
  script_version("2026-01-15T05:47:46+0000");
  script_tag(name:"last_modification", value:"2026-01-15 05:47:46 +0000 (Thu, 15 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-16 13:42:54 +0000 (Fri, 16 Feb 2024)");

  script_name("Ubuntu: Security Advisory (USN-7958-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|25\.04)");

  script_xref(name:"Advisory-ID", value:"USN-7958-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7958-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'angular.js' package(s) announced via the USN-7958-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that AngularJS did not properly sanitize certain
`xlink:href` attributes. A remote attacker could possibly use this issue
to perform cross site scripting. This issue only affected Ubuntu 16.04
LTS. (CVE-2019-14863)

It was discovered that AngularJS incorrectly handled certain regular
expressions. An attacker could possibly use this issue to cause AngularJS
to consume resources, leading to a regular expression denial of service.
This issue only affected Ubuntu 20.04 LTS, Ubuntu 22.04 LTS, Ubuntu 24.04
LTS and Ubuntu 25.04. (CVE-2022-25844)

It was discovered that AngularJS incorrectly handled certain regular
expressions. An attacker could possibly use this issue to cause AngularJS
to consume resources, leading to a regular expression denial of service.
(CVE-2023-26116, CVE-2023-26117)

It was discovered that AngularJS incorrectly handled certain regular
expressions. An attacker could possibly use this issue to cause AngularJS
to consume resources, leading to a regular expression denial of service.
This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, Ubuntu 22.04
LTS, Ubuntu 24.04 LTS and Ubuntu 25.04. (CVE-2023-26118, CVE-2024-21490)

It was discovered that AngularJS did not properly sanitize certain inputs
in HTML elements. A remote attacker could possibly use this issue to
perform spoofing and obtain sensitive information. This issue only
affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, Ubuntu 22.04 LTS, Ubuntu
24.04 LTS and Ubuntu 25.04. (CVE-2024-8372, CVE-2024-8373, CVE-2025-2336)

It was discovered that AngularJS did not properly sanitize certain inputs
in HTML elements. A remote attacker could possibly use this issue to
perform spoofing and obtain sensitive information. (CVE-2025-0716)");

  script_tag(name:"affected", value:"'angular.js' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libjs-angularjs", ver:"1.2.28-1ubuntu2+esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libjs-angularjs", ver:"1.5.10-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libjs-angularjs", ver:"1.7.9-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libjs-angularjs", ver:"1.8.2-2ubuntu0.1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libjs-angularjs", ver:"1.8.3-1ubuntu0.24.04.1", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libjs-angularjs", ver:"1.8.3-1ubuntu0.25.04.1", rls:"UBUNTU25.04"))) {
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
