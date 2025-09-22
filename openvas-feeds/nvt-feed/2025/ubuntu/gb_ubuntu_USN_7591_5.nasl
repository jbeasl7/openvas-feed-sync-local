# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7591.5");
  script_cve_id("CVE-2022-49636", "CVE-2022-49728", "CVE-2023-53034", "CVE-2024-36945", "CVE-2024-42230", "CVE-2024-46753", "CVE-2024-46812", "CVE-2024-46821", "CVE-2024-53144", "CVE-2024-56664", "CVE-2024-58093", "CVE-2024-8805", "CVE-2025-21941", "CVE-2025-21956", "CVE-2025-21957", "CVE-2025-21959", "CVE-2025-21962", "CVE-2025-21963", "CVE-2025-21964", "CVE-2025-21968", "CVE-2025-21970", "CVE-2025-21975", "CVE-2025-21981", "CVE-2025-21991", "CVE-2025-21992", "CVE-2025-21994", "CVE-2025-21996", "CVE-2025-21999", "CVE-2025-22004", "CVE-2025-22005", "CVE-2025-22007", "CVE-2025-22008", "CVE-2025-22010", "CVE-2025-22014", "CVE-2025-22018", "CVE-2025-22020", "CVE-2025-22021", "CVE-2025-22025", "CVE-2025-22035", "CVE-2025-22044", "CVE-2025-22045", "CVE-2025-22050", "CVE-2025-22054", "CVE-2025-22055", "CVE-2025-22056", "CVE-2025-22060", "CVE-2025-22063", "CVE-2025-22066", "CVE-2025-22071", "CVE-2025-22073", "CVE-2025-22075", "CVE-2025-22079", "CVE-2025-22081", "CVE-2025-22086", "CVE-2025-22089", "CVE-2025-22097", "CVE-2025-2312", "CVE-2025-23136", "CVE-2025-23138", "CVE-2025-37785", "CVE-2025-37889", "CVE-2025-37937", "CVE-2025-38152", "CVE-2025-38575", "CVE-2025-38637", "CVE-2025-39728", "CVE-2025-39735");
  script_tag(name:"creation_date", value:"2025-07-07 04:13:26 +0000 (Mon, 07 Jul 2025)");
  script_version("2025-07-07T05:42:05+0000");
  script_tag(name:"last_modification", value:"2025-07-07 05:42:05 +0000 (Mon, 07 Jul 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-20 18:05:47 +0000 (Fri, 20 Dec 2024)");

  script_name("Ubuntu: Security Advisory (USN-7591-5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7591-5");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7591-5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-intel-iotg' package(s) announced via the USN-7591-5 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Michael Randrianantenaina discovered that the Bluetooth driver in the Linux
Kernel contained an improper access control vulnerability. A nearby
attacker could use this to connect a rougue device and possibly execute
arbitrary code. (CVE-2024-8805)

It was discovered that the CIFS network file system implementation in the
Linux kernel did not properly verify the target namespace when handling
upcalls. An attacker could use this to expose sensitive information.
(CVE-2025-2312)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - PowerPC architecture,
 - x86 architecture,
 - ACPI drivers,
 - Clock framework and drivers,
 - GPU drivers,
 - HID subsystem,
 - InfiniBand drivers,
 - Media drivers,
 - MemoryStick subsystem,
 - Network drivers,
 - Mellanox network drivers,
 - NTB driver,
 - PCI subsystem,
 - Voltage and Current Regulator drivers,
 - Remote Processor subsystem,
 - SCSI subsystem,
 - QCOM SoC drivers,
 - Thermal drivers,
 - BTRFS file system,
 - Ext4 file system,
 - JFS file system,
 - Network file system (NFS) server daemon,
 - NTFS3 file system,
 - File systems infrastructure,
 - Proc file system,
 - SMB network file system,
 - IPv6 networking,
 - RDMA verbs API,
 - SoC audio core drivers,
 - Tracing infrastructure,
 - Watch queue notification mechanism,
 - 802.1Q VLAN protocol,
 - Asynchronous Transfer Mode (ATM) subsystem,
 - Bluetooth subsystem,
 - Networking core,
 - IPv4 networking,
 - Netfilter,
 - Network traffic control,
 - SMC sockets,
 - SoC Audio for Freescale CPUs drivers,
(CVE-2025-23138, CVE-2025-21956, CVE-2025-21970, CVE-2025-22025,
CVE-2024-46753, CVE-2025-21962, CVE-2025-37889, CVE-2025-21992,
CVE-2025-39728, CVE-2025-22054, CVE-2025-21959, CVE-2024-53144,
CVE-2022-49728, CVE-2024-58093, CVE-2025-38637, CVE-2025-21981,
CVE-2025-21963, CVE-2025-21968, CVE-2025-22014, CVE-2024-46812,
CVE-2025-22005, CVE-2025-21994, CVE-2025-22071, CVE-2025-22008,
CVE-2022-49636, CVE-2025-22007, CVE-2023-53034, CVE-2025-22035,
CVE-2025-22010, CVE-2025-22081, CVE-2025-22021, CVE-2024-46821,
CVE-2025-21999, CVE-2025-38575, CVE-2025-22073, CVE-2025-22004,
CVE-2024-42230, CVE-2025-21941, CVE-2024-56664, CVE-2025-22044,
CVE-2025-39735, CVE-2025-22060, CVE-2025-22055, CVE-2025-21957,
CVE-2025-21975, CVE-2025-22075, CVE-2025-22089, CVE-2025-37937,
CVE-2025-38152, CVE-2025-22020, CVE-2025-22066, CVE-2025-22056,
CVE-2025-22050, CVE-2025-21964, CVE-2025-21996, CVE-2025-22079,
CVE-2025-23136, CVE-2025-22063, CVE-2024-36945, CVE-2025-22097,
CVE-2025-37785, CVE-2025-21991, CVE-2025-22086, CVE-2025-22045,
CVE-2025-22018)");

  script_tag(name:"affected", value:"'linux-intel-iotg' package(s) on Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1081-intel-iotg", ver:"5.15.0-1081.87", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-intel-iotg", ver:"5.15.0.1081.81", rls:"UBUNTU22.04 LTS"))) {
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
