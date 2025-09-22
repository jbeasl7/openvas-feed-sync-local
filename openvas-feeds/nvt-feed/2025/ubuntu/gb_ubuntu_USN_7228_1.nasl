# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7228.1");
  script_cve_id("CVE-2024-12425", "CVE-2024-12426");
  script_tag(name:"creation_date", value:"2025-01-28 04:08:36 +0000 (Tue, 28 Jan 2025)");
  script_version("2025-01-28T05:37:13+0000");
  script_tag(name:"last_modification", value:"2025-01-28 05:37:13 +0000 (Tue, 28 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7228-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|24\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7228-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7228-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libreoffice' package(s) announced via the USN-7228-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Thomas Rinsma discovered that LibreOffice incorrectly handled paths when
processing embedded font files. If a user or automated system were tricked
into opening a specially crafted LibreOffice file, a remote attacker could
possibly use this issue to create arbitrary files ending with '.ttf'.
(CVE-2024-12425)

Thomas Rinsma discovered that LibreOffice incorrectly handled certain
environment variables and INI file values. If a user or automated system
were tricked into opening a specially crafted LibreOffice file, a remote
attacker could possibly use this issue to exfiltrate sensitive information.
(CVE-2024-12426)");

  script_tag(name:"affected", value:"'libreoffice' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 24.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice", ver:"1:6.4.7-0ubuntu0.20.04.13", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice", ver:"1:7.3.7-0ubuntu0.22.04.8", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice", ver:"4:24.2.7-0ubuntu0.24.04.2", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice", ver:"4:24.8.4-0ubuntu0.24.10.2", rls:"UBUNTU24.10"))) {
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
