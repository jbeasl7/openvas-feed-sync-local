# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6848.1");
  script_cve_id("CVE-2023-47272", "CVE-2023-5631", "CVE-2024-37383", "CVE-2024-37384");
  script_tag(name:"creation_date", value:"2024-06-26 04:08:04 +0000 (Wed, 26 Jun 2024)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-25 13:56:29 +0000 (Fri, 25 Oct 2024)");

  script_name("Ubuntu: Security Advisory (USN-6848-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6848-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6848-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2043396");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'roundcube' package(s) announced via the USN-6848-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Matthieu Faou and Denys Klymenko discovered that Roundcube incorrectly
handled certain SVG images. A remote attacker could possibly use this
issue to load arbitrary JavaScript code. This issue only affected Ubuntu
18.04 LTS, Ubuntu 20.04 LTS, Ubuntu 22.04 LTS and Ubuntu 23.10.
(CVE-2023-5631)

Rene Rehme discovered that Roundcube incorrectly handled certain headers.
A remote attacker could possibly use this issue to load arbitrary
JavaScript code. This issue only affected Ubuntu 20.04 LTS,
Ubuntu 22.04 LTS and Ubuntu 23.10. (CVE-2023-47272)

Valentin T. and Lutz Wolf discovered that Roundcube incorrectly handled
certain SVG images. A remote attacker could possibly use this issue to
load arbitrary JavaScript code. This issue only affected Ubuntu 18.04 LTS,
Ubuntu 20.04 LTS, Ubuntu 22.04 LTS and Ubuntu 23.10. (CVE-2024-37383)

Huy Nguyen Pham Nhat discovered that Roundcube incorrectly handled
certain fields in user preferences. A remote attacker could possibly use
this issue to load arbitrary JavaScript code. (CVE-2024-37384)");

  script_tag(name:"affected", value:"'roundcube' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isdpkgvuln(pkg:"roundcube", ver:"1.2~beta+dfsg.1-0ubuntu1+esm4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"roundcube-core", ver:"1.2~beta+dfsg.1-0ubuntu1+esm4", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"roundcube", ver:"1.3.6+dfsg.1-1ubuntu0.1~esm4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"roundcube-core", ver:"1.3.6+dfsg.1-1ubuntu0.1~esm4", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"roundcube", ver:"1.4.3+dfsg.1-1ubuntu0.1~esm4", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"roundcube-core", ver:"1.4.3+dfsg.1-1ubuntu0.1~esm4", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"roundcube", ver:"1.5.0+dfsg.1-2ubuntu0.1~esm3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"roundcube-core", ver:"1.5.0+dfsg.1-2ubuntu0.1~esm3", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"roundcube", ver:"1.6.2+dfsg-1ubuntu0.2", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"roundcube-core", ver:"1.6.2+dfsg-1ubuntu0.2", rls:"UBUNTU23.10"))) {
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
