# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8088.1");
  script_cve_id("CVE-2023-49568", "CVE-2023-49569", "CVE-2025-21613", "CVE-2025-21614", "CVE-2026-25934");
  script_tag(name:"creation_date", value:"2026-03-16 04:53:37 +0000 (Mon, 16 Mar 2026)");
  script_version("2026-03-16T06:13:25+0000");
  script_tag(name:"last_modification", value:"2026-03-16 06:13:25 +0000 (Mon, 16 Mar 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-12 11:15:13 +0000 (Fri, 12 Jan 2024)");

  script_name("Ubuntu: Security Advisory (USN-8088-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-8088-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8088-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-go-git-go-git' package(s) announced via the USN-8088-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ionut Lalu discovered that go-git incorrectly handled certain specially
crafted Git server responses. An attacker could possibly use this issue to
cause a denial of service. (CVE-2023-49568, CVE-2025-21614)

Ionut Lalu discovered that go-git incorrectly handled file system paths
when using the ChrootOS implementation. A remote attacker could possibly
use this issue to perform a path traversal and create or modify arbitrary
files, leading to remote code execution. (CVE-2023-49569)

It was discovered that go-git did not properly sanitize arguments when
invoking git-upload-pack using the file transport protocol. An attacker
could possibly use this issue to inject arbitrary flag values when
interacting with local Git repositories. (CVE-2025-21613)

It was discovered that go-git did not properly verify integrity checks for
pack and index files. An attacker could possibly use this issue to cause
go-git to process corrupted repository data, resulting in unexpected errors
or an incorrect repository state. (CVE-2026-25934)");

  script_tag(name:"affected", value:"'golang-github-go-git-go-git' package(s) on Ubuntu 22.04, Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"go-git", ver:"5.4.2-3ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-github-go-git-go-git-dev", ver:"5.4.2-3ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"go-git", ver:"5.4.2-4ubuntu0.24.04.3+esm2", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-github-go-git-go-git-dev", ver:"5.4.2-4ubuntu0.24.04.3+esm2", rls:"UBUNTU24.04 LTS"))) {
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
