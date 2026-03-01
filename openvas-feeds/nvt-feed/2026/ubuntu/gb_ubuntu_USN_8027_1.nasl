# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8027.1");
  script_cve_id("CVE-2024-24762", "CVE-2024-53981", "CVE-2026-24486");
  script_tag(name:"creation_date", value:"2026-02-12 11:19:52 +0000 (Thu, 12 Feb 2026)");
  script_version("2026-02-18T05:57:21+0000");
  script_tag(name:"last_modification", value:"2026-02-18 05:57:21 +0000 (Wed, 18 Feb 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-17 20:44:50 +0000 (Tue, 17 Feb 2026)");

  script_name("Ubuntu: Security Advisory (USN-8027-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-8027-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8027-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-multipart' package(s) announced via the USN-8027-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Python-Multipart incorrectly handled certain
regular expressions. An attacker could possibly use this issue to cause
Python-Multipart to consume excessive resources, leading to a regular
expression denial of service. This issue only affected Ubuntu 22.04 LTS.
(CVE-2024-24762)

It was discovered that Python-Multipart did not properly sanitize line
breaks during user input. An attacker could use this issue to send
arbitrary input, thus preventing other requests from being processed,
resulting in a denial of service. This issue was only fixed in
Ubuntu 24.04 LTS. (CVE-2024-53981)

It was discovered that Python-Multipart was vulnerable to path traversal
attacks. An attacker could possibly craft and upload files outside the
target directory, resulting in remote code execution. (CVE-2026-24486)");

  script_tag(name:"affected", value:"'python-multipart' package(s) on Ubuntu 22.04, Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python3-multipart", ver:"0.0.5-2ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3-multipart", ver:"0.0.9-1ubuntu0.1~esm1", rls:"UBUNTU24.04 LTS"))) {
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
