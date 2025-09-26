# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7755.3");
  script_cve_id("CVE-2023-52477", "CVE-2024-27074", "CVE-2024-47685", "CVE-2024-50051", "CVE-2024-50202", "CVE-2024-53130", "CVE-2024-53131", "CVE-2024-57996", "CVE-2025-37752", "CVE-2025-38350");
  script_tag(name:"creation_date", value:"2025-09-25 04:04:35 +0000 (Thu, 25 Sep 2025)");
  script_version("2025-09-25T05:39:09+0000");
  script_tag(name:"last_modification", value:"2025-09-25 05:39:09 +0000 (Thu, 25 Sep 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-23 15:19:06 +0000 (Wed, 23 Oct 2024)");

  script_name("Ubuntu: Security Advisory (USN-7755-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7755-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7755-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws-fips' package(s) announced via the USN-7755-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - Media drivers,
 - SPI subsystem,
 - USB core drivers,
 - NILFS2 file system,
 - IPv6 networking,
 - Network traffic control,
(CVE-2025-38350, CVE-2024-47685, CVE-2024-57996, CVE-2024-53130,
CVE-2025-37752, CVE-2023-52477, CVE-2024-53131, CVE-2024-50202,
CVE-2024-27074, CVE-2024-50051)");

  script_tag(name:"affected", value:"'linux-aws-fips' package(s) on Ubuntu 18.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-2122-aws-fips", ver:"4.15.0-2122.128", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-fips", ver:"4.15.0.2122.116", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-fips-4.15", ver:"4.15.0.2122.116", rls:"UBUNTU18.04 LTS"))) {
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
