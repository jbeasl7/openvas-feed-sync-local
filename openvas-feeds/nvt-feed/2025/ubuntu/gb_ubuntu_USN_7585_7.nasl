# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7585.7");
  script_cve_id("CVE-2021-47211", "CVE-2022-49636", "CVE-2023-53034", "CVE-2024-53168", "CVE-2024-56551", "CVE-2024-58093", "CVE-2025-21956", "CVE-2025-21957", "CVE-2025-21959", "CVE-2025-21991", "CVE-2025-21992", "CVE-2025-21993", "CVE-2025-21996", "CVE-2025-22004", "CVE-2025-22005", "CVE-2025-22007", "CVE-2025-22018", "CVE-2025-22020", "CVE-2025-22021", "CVE-2025-22035", "CVE-2025-22045", "CVE-2025-22054", "CVE-2025-22063", "CVE-2025-22071", "CVE-2025-22073", "CVE-2025-22079", "CVE-2025-22086", "CVE-2025-2312", "CVE-2025-23136", "CVE-2025-37937", "CVE-2025-38637", "CVE-2025-39735");
  script_tag(name:"creation_date", value:"2025-07-17 04:15:48 +0000 (Thu, 17 Jul 2025)");
  script_version("2025-07-17T05:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-17 05:43:33 +0000 (Thu, 17 Jul 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-06 16:45:15 +0000 (Tue, 06 May 2025)");

  script_name("Ubuntu: Security Advisory (USN-7585-7)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7585-7");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7585-7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-raspi, linux-raspi-5.4' package(s) announced via the USN-7585-7 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the CIFS network file system implementation in the
Linux kernel did not properly verify the target namespace when handling
upcalls. An attacker could use this to expose sensitive information.
(CVE-2025-2312)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - PowerPC architecture,
 - x86 architecture,
 - iSCSI Boot Firmware Table Attributes driver,
 - GPU drivers,
 - HID subsystem,
 - InfiniBand drivers,
 - Media drivers,
 - MemoryStick subsystem,
 - Network drivers,
 - NTB driver,
 - PCI subsystem,
 - SCSI subsystem,
 - Thermal drivers,
 - JFS file system,
 - File systems infrastructure,
 - Tracing infrastructure,
 - 802.1Q VLAN protocol,
 - Asynchronous Transfer Mode (ATM) subsystem,
 - Bluetooth subsystem,
 - IPv6 networking,
 - Netfilter,
 - Network traffic control,
 - Sun RPC protocol,
 - USB sound devices,
(CVE-2025-22007, CVE-2025-21959, CVE-2025-22021, CVE-2025-22063,
CVE-2025-22045, CVE-2024-58093, CVE-2022-49636, CVE-2025-22020,
CVE-2024-53168, CVE-2025-22071, CVE-2025-39735, CVE-2025-21991,
CVE-2025-21992, CVE-2025-21996, CVE-2025-22035, CVE-2023-53034,
CVE-2025-22054, CVE-2025-23136, CVE-2025-22073, CVE-2024-56551,
CVE-2025-22005, CVE-2025-37937, CVE-2021-47211, CVE-2025-22086,
CVE-2025-21956, CVE-2025-38637, CVE-2025-22004, CVE-2025-22018,
CVE-2025-22079, CVE-2025-21957, CVE-2025-21993)");

  script_tag(name:"affected", value:"'linux-raspi, linux-raspi-5.4' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1130-raspi", ver:"5.4.0-1130.143~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-hwe-18.04", ver:"5.4.0.1130.143~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1130-raspi", ver:"5.4.0-1130.143", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"5.4.0.1130.161", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi2", ver:"5.4.0.1130.161", rls:"UBUNTU20.04 LTS"))) {
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
