# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7643.1");
  script_cve_id("CVE-2025-32907", "CVE-2025-32914", "CVE-2025-4945", "CVE-2025-4948", "CVE-2025-4969");
  script_tag(name:"creation_date", value:"2025-07-18 04:17:04 +0000 (Fri, 18 Jul 2025)");
  script_version("2025-07-18T05:44:10+0000");
  script_tag(name:"last_modification", value:"2025-07-18 05:44:10 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-19 16:15:36 +0000 (Mon, 19 May 2025)");

  script_name("Ubuntu: Security Advisory (USN-7643-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|25\.04)");

  script_xref(name:"Advisory-ID", value:"USN-7643-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7643-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsoup2.4, libsoup3' package(s) announced via the USN-7643-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jan Rozanski discovered that libsoup incorrectly handled range headers in
an HTTP request. An attacker could possibly use this issue to cause libsoup
to consume excessive memory, resulting in a denial of service.
(CVE-2025-32907)

Alon Zahavi discovered that libsoup incorrectly handled memory when parsing
HTTP requests. An attacker could possibly use this issue to send a
maliciously crafted HTTP request to the server, causing a denial of service
or obtaining sensitive information. This issue only affected Ubuntu 25.04.
(CVE-2025-32914)

It was discovered that libsoup incorrectly handled memory when parsing
the expiration date of maliciously crafted cookies. An attacker could
possibly use this issue to cause a denial of service. (CVE-2025-4945)

It was discovered that libsoup incorrectly handled integer calculations
when parsing multipart data. An attacker could possibly use this issue to
cause a denial of service. (CVE-2025-4948)

It was discovered that libsoup incorrectly handled buffer reading when
locating boundaries in multipart forms. An attacker could possibly use this
issue to cause a denial of service or obtain sensitive information.
(CVE-2025-4969)");

  script_tag(name:"affected", value:"'libsoup2.4, libsoup3' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libsoup2.4-1", ver:"2.52.2-1ubuntu0.3+esm5", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libsoup2.4-1", ver:"2.62.1-1ubuntu0.4+esm6", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libsoup2.4-1", ver:"2.70.0-1ubuntu0.5+esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libsoup-3.0-0", ver:"3.0.7-0ubuntu1+esm5", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsoup2.4-1", ver:"2.74.2-3ubuntu0.6", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libsoup-2.4-1", ver:"2.74.3-6ubuntu1.6", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsoup-3.0-0", ver:"3.4.4-5ubuntu0.5", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libsoup-2.4-1", ver:"2.74.3-10ubuntu0.4", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsoup-3.0-0", ver:"3.6.5-1ubuntu0.2", rls:"UBUNTU25.04"))) {
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
