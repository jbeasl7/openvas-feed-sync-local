# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7472.1");
  script_cve_id("CVE-2021-42553", "CVE-2024-8946", "CVE-2024-8947");
  script_tag(name:"creation_date", value:"2025-05-02 04:04:40 +0000 (Fri, 02 May 2025)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-24 15:55:19 +0000 (Mon, 24 Oct 2022)");

  script_name("Ubuntu: Security Advisory (USN-7472-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|24\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7472-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7472-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'micropython' package(s) announced via the USN-7472-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Junwha Hong and Wonil Jang discovered that Micropython incorrectly handled
the length of a buffer in mp_vfs_umount, leading to a heap-based buffer
overflow vulnerability. If a user or automated system were tricked into
opening a specially crafted file, an attacker could possibly use this issue
to cause a denial of service or possibly execute arbitrary code.
(CVE-2024-8946)


Junwha Hong and Wonil Jang discovered that Micropython incorrectly handled
memory, leading to a use-after-free vulnerability under certain
circumstances. If a user or automated system were tricked into opening a
specially crafted file, an attacker could possibly use this issue to
cause a denial of service or possibly execute arbitrary code.
(CVE-2024-8947)

It was discovered that Middleware USB Host MCU Component incorrectly
handled memory, leading to a buffer overflow vulnerability, If a user or
automated system were tricked into opening a specially crafted file, an
attacker could possibly use this issue to cause a denial of service or
possibly execute arbitrary code. (CVE-2021-42553)");

  script_tag(name:"affected", value:"'micropython' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 24.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"micropython", ver:"1.12-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"micropython", ver:"1.17+ds-1.1ubuntu2+esm1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"micropython", ver:"1.22.1+ds-1ubuntu0.24.04.1~esm1", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"micropython", ver:"1.22.1+ds-1ubuntu0.24.10.1", rls:"UBUNTU24.10"))) {
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
