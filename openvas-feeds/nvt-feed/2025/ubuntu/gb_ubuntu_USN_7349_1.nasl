# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7349.1");
  script_cve_id("CVE-2022-30333", "CVE-2023-40477");
  script_tag(name:"creation_date", value:"2025-03-13 04:04:12 +0000 (Thu, 13 Mar 2025)");
  script_version("2025-03-13T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-03-13 05:38:41 +0000 (Thu, 13 Mar 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-17 17:51:36 +0000 (Tue, 17 May 2022)");

  script_name("Ubuntu: Security Advisory (USN-7349-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7349-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7349-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rar' package(s) announced via the USN-7349-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that RAR incorrectly handled certain paths. If a user or
automated system were tricked into extracting a specially crafted RAR
archive, a remote attacker could possibly use this issue to write arbitrary
files outside of the targeted directory. (CVE-2022-30333)

It was discovered that RAR incorrectly handled certain recovery volumes. If
a user or automated system were tricked into extracting a specially crafted
RAR archive, a remote attacker could possibly use this issue to execute
arbitrary code. (CVE-2023-40477)");

  script_tag(name:"affected", value:"'rar' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"rar", ver:"2:6.23-1~20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"rar", ver:"2:6.23-1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
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
