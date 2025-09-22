# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7475.1");
  script_cve_id("CVE-2022-0995", "CVE-2024-26837", "CVE-2024-26928", "CVE-2024-35864", "CVE-2024-46826", "CVE-2024-50248", "CVE-2024-50256", "CVE-2024-56651", "CVE-2024-56658", "CVE-2024-57798", "CVE-2025-21700", "CVE-2025-21701", "CVE-2025-21702", "CVE-2025-21703", "CVE-2025-21756", "CVE-2025-21993");
  script_tag(name:"creation_date", value:"2025-05-05 04:05:19 +0000 (Mon, 05 May 2025)");
  script_version("2025-05-05T05:40:25+0000");
  script_tag(name:"last_modification", value:"2025-05-05 05:40:25 +0000 (Mon, 05 May 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-03 14:53:23 +0000 (Mon, 03 Feb 2025)");

  script_name("Ubuntu: Security Advisory (USN-7475-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7475-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7475-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-xilinx-zynqmp' package(s) announced via the USN-7475-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jann Horn discovered that the watch_queue event notification subsystem in
the Linux kernel contained an out-of-bounds write vulnerability. A local
attacker could use this to cause a denial of service (system crash) or
escalate their privileges. (CVE-2022-0995)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - iSCSI Boot Firmware Table Attributes driver,
 - GPU drivers,
 - Network drivers,
 - File systems infrastructure,
 - NTFS3 file system,
 - SMB network file system,
 - Network namespace,
 - Ethernet bridge,
 - Networking core,
 - Ethtool driver,
 - IPv6 networking,
 - Network traffic control,
 - VMware vSockets driver,
(CVE-2024-50248, CVE-2024-57798, CVE-2025-21702, CVE-2024-56651,
CVE-2024-26837, CVE-2025-21703, CVE-2024-46826, CVE-2025-21700,
CVE-2024-50256, CVE-2024-35864, CVE-2025-21756, CVE-2025-21993,
CVE-2024-26928, CVE-2024-56658, CVE-2025-21701)");

  script_tag(name:"affected", value:"'linux-xilinx-zynqmp' package(s) on Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1046-xilinx-zynqmp", ver:"5.15.0-1046.50", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-xilinx-zynqmp", ver:"5.15.0.1046.50", rls:"UBUNTU22.04 LTS"))) {
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
