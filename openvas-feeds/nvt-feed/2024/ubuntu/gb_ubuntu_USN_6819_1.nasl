# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6819.1");
  script_cve_id("CVE-2023-52443", "CVE-2023-52444", "CVE-2023-52445", "CVE-2023-52446", "CVE-2023-52447", "CVE-2023-52448", "CVE-2023-52449", "CVE-2023-52450", "CVE-2023-52451", "CVE-2023-52452", "CVE-2023-52453", "CVE-2023-52454", "CVE-2023-52455", "CVE-2023-52456", "CVE-2023-52457", "CVE-2023-52458", "CVE-2023-52462", "CVE-2023-52463", "CVE-2023-52464", "CVE-2023-52465", "CVE-2023-52467", "CVE-2023-52468", "CVE-2023-52469", "CVE-2023-52470", "CVE-2023-52472", "CVE-2023-52473", "CVE-2023-52486", "CVE-2023-52487", "CVE-2023-52488", "CVE-2023-52489", "CVE-2023-52490", "CVE-2023-52491", "CVE-2023-52492", "CVE-2023-52493", "CVE-2023-52494", "CVE-2023-52495", "CVE-2023-52497", "CVE-2023-52498", "CVE-2023-52583", "CVE-2023-52584", "CVE-2023-52587", "CVE-2023-52588", "CVE-2023-52589", "CVE-2023-52591", "CVE-2023-52593", "CVE-2023-52594", "CVE-2023-52595", "CVE-2023-52597", "CVE-2023-52598", "CVE-2023-52599", "CVE-2023-52606", "CVE-2023-52607", "CVE-2023-52608", "CVE-2023-52609", "CVE-2023-52610", "CVE-2023-52611", "CVE-2023-52612", "CVE-2023-52614", "CVE-2023-52616", "CVE-2023-52617", "CVE-2023-52618", "CVE-2023-52619", "CVE-2023-52621", "CVE-2023-52622", "CVE-2023-52623", "CVE-2023-52626", "CVE-2023-52627", "CVE-2023-52632", "CVE-2023-52633", "CVE-2023-52635", "CVE-2023-52664", "CVE-2023-52666", "CVE-2023-52667", "CVE-2023-52669", "CVE-2023-52670", "CVE-2023-52672", "CVE-2023-52674", "CVE-2023-52675", "CVE-2023-52676", "CVE-2023-52677", "CVE-2023-52678", "CVE-2023-52679", "CVE-2023-52680", "CVE-2023-52681", "CVE-2023-52682", "CVE-2023-52683", "CVE-2023-52685", "CVE-2023-52686", "CVE-2023-52687", "CVE-2023-52690", "CVE-2023-52691", "CVE-2023-52692", "CVE-2023-52693", "CVE-2023-52694", "CVE-2023-52696", "CVE-2023-52697", "CVE-2023-52698", "CVE-2023-6356", "CVE-2023-6535", "CVE-2023-6536", "CVE-2024-23849", "CVE-2024-24860", "CVE-2024-26582", "CVE-2024-26583", "CVE-2024-26584", "CVE-2024-26585", "CVE-2024-26586", "CVE-2024-26592", "CVE-2024-26594", "CVE-2024-26595", "CVE-2024-26598", "CVE-2024-26607", "CVE-2024-26608", "CVE-2024-26610", "CVE-2024-26612", "CVE-2024-26615", "CVE-2024-26616", "CVE-2024-26618", "CVE-2024-26620", "CVE-2024-26623", "CVE-2024-26625", "CVE-2024-26627", "CVE-2024-26629", "CVE-2024-26631", "CVE-2024-26632", "CVE-2024-26633", "CVE-2024-26634", "CVE-2024-26636", "CVE-2024-26638", "CVE-2024-26640", "CVE-2024-26641", "CVE-2024-26644", "CVE-2024-26645", "CVE-2024-26646", "CVE-2024-26647", "CVE-2024-26649", "CVE-2024-26668", "CVE-2024-26669", "CVE-2024-26670", "CVE-2024-26671", "CVE-2024-26673", "CVE-2024-26808", "CVE-2024-35835", "CVE-2024-35837", "CVE-2024-35838", "CVE-2024-35839", "CVE-2024-35840", "CVE-2024-35841", "CVE-2024-35842");
  script_tag(name:"creation_date", value:"2024-06-10 04:08:46 +0000 (Mon, 10 Jun 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-07 20:17:40 +0000 (Tue, 07 Jan 2025)");

  script_name("Ubuntu: Security Advisory (USN-6819-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6819-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6819-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure, linux-azure-6.5, linux-starfive, linux-starfive-6.5' package(s) announced via the USN-6819-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alon Zahavi discovered that the NVMe-oF/TCP subsystem in the Linux kernel
did not properly validate H2C PDU data, leading to a null pointer
dereference vulnerability. A remote attacker could use this to cause a
denial of service (system crash). (CVE-2023-6356, CVE-2023-6535,
CVE-2023-6536)

Chenyuan Yang discovered that the RDS Protocol implementation in the Linux
kernel contained an out-of-bounds read vulnerability. An attacker could use
this to possibly cause a denial of service (system crash). (CVE-2024-23849)

It was discovered that a race condition existed in the Bluetooth subsystem
in the Linux kernel, leading to a null pointer dereference vulnerability. A
privileged local attacker could use this to possibly cause a denial of
service (system crash). (CVE-2024-24860)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - ARM64 architecture,
 - PowerPC architecture,
 - RISC-V architecture,
 - S390 architecture,
 - Core kernel,
 - x86 architecture,
 - Block layer subsystem,
 - Cryptographic API,
 - ACPI drivers,
 - Android drivers,
 - Drivers core,
 - Power management core,
 - Bus devices,
 - Device frequency scaling framework,
 - DMA engine subsystem,
 - EDAC drivers,
 - ARM SCMI message protocol,
 - GPU drivers,
 - IIO ADC drivers,
 - InfiniBand drivers,
 - IOMMU subsystem,
 - Media drivers,
 - Multifunction device drivers,
 - MTD block device drivers,
 - Network drivers,
 - NVME drivers,
 - Device tree and open firmware driver,
 - PCI driver for MicroSemi Switchtec,
 - Power supply drivers,
 - RPMSG subsystem,
 - SCSI drivers,
 - QCOM SoC drivers,
 - SPMI drivers,
 - Thermal drivers,
 - TTY drivers,
 - VFIO drivers,
 - BTRFS file system,
 - Ceph distributed file system,
 - EFI Variable file system,
 - EROFS file system,
 - Ext4 file system,
 - F2FS file system,
 - GFS2 file system,
 - JFS file system,
 - Network file systems library,
 - Network file system server daemon,
 - File systems infrastructure,
 - Pstore file system,
 - ReiserFS file system,
 - SMB network file system,
 - BPF subsystem,
 - Memory management,
 - TLS protocol,
 - Ethernet bridge,
 - Networking core,
 - IPv4 networking,
 - IPv6 networking,
 - Logical Link layer,
 - MAC80211 subsystem,
 - Multipath TCP,
 - Netfilter,
 - NetLabel subsystem,
 - Network traffic control,
 - SMC sockets,
 - Sun RPC protocol,
 - AppArmor security module,
 - Intel ASoC drivers,
 - MediaTek ASoC drivers,
 - USB sound devices,
(CVE-2023-52612, CVE-2024-26808, CVE-2023-52691, CVE-2023-52618,
CVE-2023-52463, CVE-2023-52447, CVE-2024-26668, CVE-2023-52454,
CVE-2024-26670, CVE-2024-26646, CVE-2023-52472, CVE-2024-26586,
CVE-2023-52681, CVE-2023-52453, CVE-2023-52611, CVE-2023-52622,
CVE-2024-26641, CVE-2023-52616, CVE-2024-26592, CVE-2023-52606,
CVE-2024-26620, CVE-2023-52692, CVE-2024-26669, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-azure, linux-azure-6.5, linux-starfive, linux-starfive-6.5' package(s) on Ubuntu 22.04, Ubuntu 23.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1015-starfive", ver:"6.5.0-1015.16~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1022-azure", ver:"6.5.0-1022.23~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1022-azure-fde", ver:"6.5.0-1022.23~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"6.5.0.1022.23~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-fde", ver:"6.5.0.1022.23~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-starfive", ver:"6.5.0.1015.16~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1015-starfive", ver:"6.5.0-1015.16", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1022-azure", ver:"6.5.0-1022.23", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1022-azure-fde", ver:"6.5.0-1022.23", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"6.5.0.1022.26", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-fde", ver:"6.5.0.1022.26", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-starfive", ver:"6.5.0.1015.17", rls:"UBUNTU23.10"))) {
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
