# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6807.1");
  script_cve_id("CVE-2022-26126", "CVE-2022-26127", "CVE-2022-26128", "CVE-2022-26129", "CVE-2022-37032", "CVE-2022-37035", "CVE-2023-31490", "CVE-2023-38406", "CVE-2023-38407", "CVE-2023-38802", "CVE-2023-46752", "CVE-2023-46753", "CVE-2023-47234", "CVE-2023-47235", "CVE-2024-31948");
  script_tag(name:"creation_date", value:"2024-06-06 04:07:45 +0000 (Thu, 06 Jun 2024)");
  script_version("2024-06-06T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-06-06 05:05:36 +0000 (Thu, 06 Jun 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-14 20:03:32 +0000 (Tue, 14 Nov 2023)");

  script_name("Ubuntu: Security Advisory (USN-6807-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6807-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6807-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'frr' package(s) announced via the USN-6807-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that FRR incorrectly handled certain network traffic.
A remote attacker could possibly use this issue to cause FRR to crash,
resulting in a denial of service. (CVE-2022-26126, CVE-2022-26127,
CVE-2022-26128, CVE-2022-26129, CVE-2022-37032, CVE-2022-37035,
CVE-2023-31490, CVE-2023-38406, CVE-2023-38407, CVE-2023-46752,
CVE-2023-46753, CVE-2023-47234, CVE-2023-47235, CVE-2024-31948)

Ben Cartwright-Cox discovered that FRR incorrectly handled certain
network traffic. A remote attacker could possibly use this issue to cause
FRR to crash, resulting in a denial of service. (CVE-2023-38802)");

  script_tag(name:"affected", value:"'frr' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"frr", ver:"7.2.1-1ubuntu0.2+esm2", rls:"UBUNTU20.04 LTS"))) {
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
