# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7429.2");
  script_cve_id("CVE-2021-47119", "CVE-2021-47122", "CVE-2021-47235", "CVE-2021-47320", "CVE-2021-47483", "CVE-2021-47602", "CVE-2024-26863", "CVE-2024-26921", "CVE-2024-46826", "CVE-2024-49948", "CVE-2024-49952", "CVE-2024-50167", "CVE-2024-50265", "CVE-2024-50302", "CVE-2024-53165", "CVE-2024-53227", "CVE-2024-56595", "CVE-2024-56600", "CVE-2024-56658", "CVE-2025-21700", "CVE-2025-21702");
  script_tag(name:"creation_date", value:"2025-04-10 04:04:34 +0000 (Thu, 10 Apr 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-06 19:29:49 +0000 (Mon, 06 Jan 2025)");

  script_name("Ubuntu: Security Advisory (USN-7429-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7429-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7429-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-fips' package(s) announced via the USN-7429-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - Drivers core,
 - HID subsystem,
 - Network drivers,
 - SCSI subsystem,
 - SuperH / SH-Mobile drivers,
 - File systems infrastructure,
 - Ext4 file system,
 - JFS file system,
 - Network file system (NFS) client,
 - Memory management,
 - Network namespace,
 - CAIF protocol,
 - Networking core,
 - HSR network protocol,
 - IPv4 networking,
 - IPv6 networking,
 - MAC80211 subsystem,
 - Network traffic control,
(CVE-2025-21702, CVE-2024-53227, CVE-2024-46826, CVE-2024-49952,
CVE-2024-56600, CVE-2021-47235, CVE-2024-50265, CVE-2021-47119,
CVE-2024-53165, CVE-2021-47483, CVE-2024-50302, CVE-2024-56595,
CVE-2024-50167, CVE-2024-56658, CVE-2024-49948, CVE-2024-26921,
CVE-2021-47602, CVE-2024-26863, CVE-2021-47320, CVE-2025-21700,
CVE-2021-47122)");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1112-fips", ver:"4.4.0-1112.119", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-fips", ver:"4.4.0.1112.113", rls:"UBUNTU16.04 LTS"))) {
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
