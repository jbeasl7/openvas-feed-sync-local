# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7633.1");
  script_cve_id("CVE-2024-27297", "CVE-2024-38531", "CVE-2024-45593", "CVE-2024-47174");
  script_tag(name:"creation_date", value:"2025-07-16 04:16:04 +0000 (Wed, 16 Jul 2025)");
  script_version("2025-07-16T05:43:53+0000");
  script_tag(name:"last_modification", value:"2025-07-16 05:43:53 +0000 (Wed, 16 Jul 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-20 19:57:55 +0000 (Fri, 20 Sep 2024)");

  script_name("Ubuntu: Security Advisory (USN-7633-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7633-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7633-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nix' package(s) announced via the USN-7633-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Linus Heckemann discovered that Nix did not correctly handle certain
binaries. An attacker could possibly use this issue to execute
arbitrary code. (CVE-2024-38531)

Pierre-Etienne Meunier discovered that Nix did not correctly handle TLS
certificates. A remote attacker could possibly use this issue to leak
sensitive information. (CVE-2024-47174)

It was discovered that Nix did not correctly handle Unix sockets. An
attacker could possibly use this issue execute arbitrary code. This issue
only affected Ubuntu 24.04 LTS. (CVE-2024-27297)

It was discovered that Nix did not correctly handle unpacking Nix
archives (NARS). If a user or automated system were tricked into opening
a specially crafted file, an attacker could possibly use this issue to
cause a denial of service or execute arbitrary code. (CVE-2024-45593)");

  script_tag(name:"affected", value:"'nix' package(s) on Ubuntu 22.04, Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"nix-bin", ver:"2.6.0+dfsg-3ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"nix-bin", ver:"2.18.1+dfsg-1ubuntu5+esm2", rls:"UBUNTU24.04 LTS"))) {
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
