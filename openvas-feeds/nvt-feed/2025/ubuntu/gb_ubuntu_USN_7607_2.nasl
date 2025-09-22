# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7607.2");
  script_cve_id("CVE-2021-47260", "CVE-2021-47576", "CVE-2022-3640", "CVE-2022-49909", "CVE-2024-46787", "CVE-2024-49958", "CVE-2024-50116", "CVE-2024-53197", "CVE-2025-37798", "CVE-2025-37932");
  script_tag(name:"creation_date", value:"2025-07-03 04:12:00 +0000 (Thu, 03 Jul 2025)");
  script_version("2025-07-03T05:42:53+0000");
  script_tag(name:"last_modification", value:"2025-07-03 05:42:53 +0000 (Thu, 03 Jul 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-24 18:50:47 +0000 (Mon, 24 Oct 2022)");

  script_name("Ubuntu: Security Advisory (USN-7607-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7607-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7607-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-fips' package(s) announced via the USN-7607-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a use-after-free vulnerability existed in the
Bluetooth stack in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2022-3640)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - SCSI subsystem,
 - Network file system (NFS) client,
 - NILFS2 file system,
 - File systems infrastructure,
 - Memory management,
 - Bluetooth subsystem,
 - Network traffic control,
 - USB sound devices,
(CVE-2024-50116, CVE-2021-47576, CVE-2024-53197, CVE-2024-46787,
CVE-2025-37798, CVE-2024-49958, CVE-2021-47260, CVE-2025-37932,
CVE-2022-49909)");

  script_tag(name:"affected", value:"'linux-fips' package(s) on Ubuntu 16.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1115-fips", ver:"4.4.0-1115.122", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-fips", ver:"4.4.0.1115.116", rls:"UBUNTU16.04 LTS"))) {
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
