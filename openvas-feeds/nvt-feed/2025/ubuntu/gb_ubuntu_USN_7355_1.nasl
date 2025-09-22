# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7355.1");
  script_cve_id("CVE-2023-37271", "CVE-2023-41039", "CVE-2024-47532", "CVE-2025-22153");
  script_tag(name:"creation_date", value:"2025-03-20 04:04:13 +0000 (Thu, 20 Mar 2025)");
  script_version("2025-03-20T05:38:32+0000");
  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-19 18:32:26 +0000 (Wed, 19 Jul 2023)");

  script_name("Ubuntu: Security Advisory (USN-7355-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|24\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7355-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7355-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'restrictedpython' package(s) announced via the USN-7355-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nakul Choudhary and Robert Xiao discovered that RestrictedPython did not
properly sanitize certain inputs. An attacker could possibly use this
issue to execute arbitrary code. This issue only affected
Ubuntu 20.04 LTS and Ubuntu 22.04 LTS. (CVE-2023-37271)

Abhishek Govindarasu, Ankush Menat and Ward Theunisse discovered that
RestrictedPython did not correctly handle certain format strings. An
attacker could possibly use this issue to leak sensitive information.
This issue only affected Ubuntu 20.04 LTS and Ubuntu 22.04 LTS.
(CVE-2023-41039)

It was discovered that RestrictedPython did not correctly restrict access
to certain fields. An attacker could possibly use this issue to leak
sensitive information. (CVE-2024-47532)

It was discovered that RestrictedPython contained a type confusion
vulnerability. An attacker could possibly use this issue to execute
arbitrary code. This issue only affected Ubuntu 24.04 LTS and
Ubuntu 24.10. (CVE-2025-22153)");

  script_tag(name:"affected", value:"'restrictedpython' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 24.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python3-restrictedpython", ver:"4.0~b3-2ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3-restrictedpython", ver:"4.0~b3-3ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3-restrictedpython", ver:"6.2-1ubuntu0.24.04.1~esm1", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3-restrictedpython", ver:"6.2-1ubuntu0.24.10.1", rls:"UBUNTU24.10"))) {
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
