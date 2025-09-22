# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7579.1");
  script_cve_id("CVE-2019-2126", "CVE-2021-26825", "CVE-2021-26826");
  script_tag(name:"creation_date", value:"2025-06-19 04:09:12 +0000 (Thu, 19 Jun 2025)");
  script_version("2025-06-19T05:40:14+0000");
  script_tag(name:"last_modification", value:"2025-06-19 05:40:14 +0000 (Thu, 19 Jun 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-22 19:16:42 +0000 (Thu, 22 Aug 2019)");

  script_name("Ubuntu: Security Advisory (USN-7579-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|24\.10|25\.04)");

  script_xref(name:"Advisory-ID", value:"USN-7579-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7579-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'godot' package(s) announced via the USN-7579-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Godot Engine did not properly handle
certain malformed WebM media files. If the Godot Engine opened a
specially crafted WebM file, a remote attacker could cause a denial
of service, or possibly execute arbitrary code. (CVE-2019-2126)

It was discovered that the Godot Engine did not properly handle
certain malformed TGA image files. If the Godot Engine opened a
specially crafted TGA image file, a remote attacker could cause
a denial of service, or possibly execute arbitrary code. This
issue only affected Ubuntu 20.04 LTS and Ubuntu 22.04 LTS.
(CVE-2021-26825, CVE-2021-26826)");

  script_tag(name:"affected", value:"'godot' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 24.10, Ubuntu 25.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"godot3", ver:"3.2-stable-2ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"godot3-runner", ver:"3.2-stable-2ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"godot3", ver:"3.2.3-stable-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"godot3-runner", ver:"3.2.3-stable-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"godot3", ver:"3.5.2-stable-2ubuntu0.24.04.1~esm1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"godot3-runner", ver:"3.5.2-stable-2ubuntu0.24.04.1~esm1", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"godot3", ver:"3.5.2-stable-2ubuntu0.24.10.1", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"godot3-runner", ver:"3.5.2-stable-2ubuntu0.24.10.1", rls:"UBUNTU24.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"godot3", ver:"3.6+ds-2ubuntu0.1", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"godot3-runner", ver:"3.6+ds-2ubuntu0.1", rls:"UBUNTU25.04"))) {
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
