# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7006.1");
  script_cve_id("CVE-2021-46926", "CVE-2023-52629", "CVE-2023-52760", "CVE-2023-52803", "CVE-2023-52887", "CVE-2024-24860", "CVE-2024-26830", "CVE-2024-26921", "CVE-2024-26929", "CVE-2024-36894", "CVE-2024-36901", "CVE-2024-36974", "CVE-2024-36978", "CVE-2024-37078", "CVE-2024-38619", "CVE-2024-39469", "CVE-2024-39484", "CVE-2024-39487", "CVE-2024-39495", "CVE-2024-39499", "CVE-2024-39501", "CVE-2024-39502", "CVE-2024-39503", "CVE-2024-39505", "CVE-2024-39506", "CVE-2024-39509", "CVE-2024-40901", "CVE-2024-40902", "CVE-2024-40904", "CVE-2024-40905", "CVE-2024-40912", "CVE-2024-40916", "CVE-2024-40932", "CVE-2024-40934", "CVE-2024-40941", "CVE-2024-40942", "CVE-2024-40943", "CVE-2024-40945", "CVE-2024-40958", "CVE-2024-40959", "CVE-2024-40960", "CVE-2024-40961", "CVE-2024-40963", "CVE-2024-40968", "CVE-2024-40974", "CVE-2024-40978", "CVE-2024-40980", "CVE-2024-40981", "CVE-2024-40984", "CVE-2024-40987", "CVE-2024-40988", "CVE-2024-40995", "CVE-2024-41006", "CVE-2024-41007", "CVE-2024-41034", "CVE-2024-41035", "CVE-2024-41041", "CVE-2024-41044", "CVE-2024-41046", "CVE-2024-41049", "CVE-2024-41087", "CVE-2024-41089", "CVE-2024-41095", "CVE-2024-41097", "CVE-2024-42070", "CVE-2024-42076", "CVE-2024-42084", "CVE-2024-42086", "CVE-2024-42087", "CVE-2024-42089", "CVE-2024-42090", "CVE-2024-42092", "CVE-2024-42093", "CVE-2024-42094", "CVE-2024-42096", "CVE-2024-42097", "CVE-2024-42101", "CVE-2024-42102", "CVE-2024-42104", "CVE-2024-42105", "CVE-2024-42106", "CVE-2024-42115", "CVE-2024-42119", "CVE-2024-42124", "CVE-2024-42127", "CVE-2024-42145", "CVE-2024-42148", "CVE-2024-42153", "CVE-2024-42154", "CVE-2024-42157", "CVE-2024-42223", "CVE-2024-42224", "CVE-2024-42232", "CVE-2024-42236");
  script_tag(name:"creation_date", value:"2024-09-13 04:07:39 +0000 (Fri, 13 Sep 2024)");
  script_version("2024-10-03T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-10-03 05:05:33 +0000 (Thu, 03 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-05 17:46:27 +0000 (Thu, 05 Sep 2024)");

  script_name("Ubuntu: Security Advisory (USN-7006-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7006-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7006-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-iot' package(s) announced via the USN-7006-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a race condition existed in the Bluetooth subsystem
in the Linux kernel, leading to a null pointer dereference vulnerability. A
privileged local attacker could use this to possibly cause a denial of
service (system crash). (CVE-2024-24860)

It was discovered that the JFS file system contained an out-of-bounds read
vulnerability when printing xattr debug information. A local attacker could
use this to cause a denial of service (system crash). (CVE-2024-40902)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - MIPS architecture,
 - PowerPC architecture,
 - SuperH RISC architecture,
 - x86 architecture,
 - ACPI drivers,
 - Serial ATA and Parallel ATA drivers,
 - Drivers core,
 - GPIO subsystem,
 - GPU drivers,
 - Greybus drivers,
 - HID subsystem,
 - I2C subsystem,
 - IIO subsystem,
 - InfiniBand drivers,
 - Media drivers,
 - VMware VMCI Driver,
 - MMC subsystem,
 - Network drivers,
 - Pin controllers subsystem,
 - S/390 drivers,
 - SCSI drivers,
 - USB subsystem,
 - GFS2 file system,
 - JFFS2 file system,
 - JFS file system,
 - File systems infrastructure,
 - NILFS2 file system,
 - IOMMU subsystem,
 - Sun RPC protocol,
 - Netfilter,
 - Memory management,
 - B.A.T.M.A.N. meshing protocol,
 - CAN network layer,
 - Ceph Core library,
 - Networking core,
 - IPv4 networking,
 - IPv6 networking,
 - IUCV driver,
 - MAC80211 subsystem,
 - NET/ROM layer,
 - Network traffic control,
 - HD-audio driver,
 - SoC Audio for Freescale CPUs drivers,
(CVE-2024-42154, CVE-2024-42093, CVE-2024-42096, CVE-2024-40984,
CVE-2024-39502, CVE-2024-36901, CVE-2024-41044, CVE-2024-40961,
CVE-2024-40981, CVE-2024-42236, CVE-2024-42232, CVE-2024-41041,
CVE-2024-40958, CVE-2024-40905, CVE-2024-42084, CVE-2024-40934,
CVE-2024-42124, CVE-2024-39505, CVE-2024-39506, CVE-2024-39501,
CVE-2021-46926, CVE-2024-40941, CVE-2024-42145, CVE-2024-41089,
CVE-2024-40932, CVE-2024-42224, CVE-2024-41097, CVE-2024-40959,
CVE-2024-42157, CVE-2024-39469, CVE-2024-39499, CVE-2024-40974,
CVE-2024-42094, CVE-2024-36894, CVE-2024-42087, CVE-2024-42104,
CVE-2023-52803, CVE-2024-41034, CVE-2024-40995, CVE-2023-52629,
CVE-2024-40912, CVE-2024-39484, CVE-2024-41006, CVE-2023-52760,
CVE-2024-41095, CVE-2024-41046, CVE-2024-42070, CVE-2023-52887,
CVE-2024-40960, CVE-2024-41007, CVE-2024-40901, CVE-2024-42119,
CVE-2024-40987, CVE-2024-42148, CVE-2024-41049, CVE-2024-40963,
CVE-2024-41087, CVE-2024-42223, CVE-2024-42090, CVE-2024-42105,
CVE-2024-42089, CVE-2024-40916, CVE-2024-40942, CVE-2024-40978,
CVE-2024-40902, CVE-2024-26921, CVE-2024-39495, CVE-2024-40943,
CVE-2024-36978, CVE-2024-26929, CVE-2024-40988, CVE-2024-39503,
CVE-2024-42101, CVE-2024-40904, CVE-2024-42086, CVE-2024-42106,
CVE-2024-26830, CVE-2024-41035, CVE-2024-42153, CVE-2024-39509,
CVE-2024-37078, CVE-2024-42076, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-iot' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1043-iot", ver:"5.4.0-1043.44", rls:"UBUNTU20.04 LTS"))) {
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
