# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7721.1");
  script_cve_id("CVE-2025-37891", "CVE-2025-37894", "CVE-2025-37895", "CVE-2025-37896", "CVE-2025-37897", "CVE-2025-37898", "CVE-2025-37899", "CVE-2025-37900", "CVE-2025-37901", "CVE-2025-37903", "CVE-2025-37904", "CVE-2025-37905", "CVE-2025-37906", "CVE-2025-37907", "CVE-2025-37908", "CVE-2025-37909", "CVE-2025-37910", "CVE-2025-37911", "CVE-2025-37912", "CVE-2025-37913", "CVE-2025-37914", "CVE-2025-37915", "CVE-2025-37916", "CVE-2025-37917", "CVE-2025-37918", "CVE-2025-37919", "CVE-2025-37920", "CVE-2025-37921", "CVE-2025-37922", "CVE-2025-37923", "CVE-2025-37924", "CVE-2025-37926", "CVE-2025-37927", "CVE-2025-37928", "CVE-2025-37929", "CVE-2025-37930", "CVE-2025-37931", "CVE-2025-37933", "CVE-2025-37934", "CVE-2025-37935", "CVE-2025-37936", "CVE-2025-37946", "CVE-2025-37947", "CVE-2025-37948", "CVE-2025-37949", "CVE-2025-37950", "CVE-2025-37951", "CVE-2025-37952", "CVE-2025-37954", "CVE-2025-37955", "CVE-2025-37956", "CVE-2025-37957", "CVE-2025-37958", "CVE-2025-37959", "CVE-2025-37960", "CVE-2025-37961", "CVE-2025-37962", "CVE-2025-37963", "CVE-2025-37964", "CVE-2025-37965", "CVE-2025-37966", "CVE-2025-37967", "CVE-2025-37968", "CVE-2025-37969", "CVE-2025-37970", "CVE-2025-37971", "CVE-2025-37972", "CVE-2025-37973", "CVE-2025-37974", "CVE-2025-37990", "CVE-2025-37991", "CVE-2025-37992", "CVE-2025-37993", "CVE-2025-37994", "CVE-2025-37995", "CVE-2025-37996", "CVE-2025-37998", "CVE-2025-37999", "CVE-2025-38002", "CVE-2025-38005", "CVE-2025-38006", "CVE-2025-38007", "CVE-2025-38008", "CVE-2025-38009", "CVE-2025-38010", "CVE-2025-38011", "CVE-2025-38012", "CVE-2025-38013", "CVE-2025-38014", "CVE-2025-38015", "CVE-2025-38016", "CVE-2025-38018", "CVE-2025-38019", "CVE-2025-38020", "CVE-2025-38021", "CVE-2025-38022", "CVE-2025-38023", "CVE-2025-38024", "CVE-2025-38025", "CVE-2025-38027", "CVE-2025-38028", "CVE-2025-38056", "CVE-2025-38083", "CVE-2025-38094", "CVE-2025-38095", "CVE-2025-38216");
  script_tag(name:"creation_date", value:"2025-08-29 04:04:21 +0000 (Fri, 29 Aug 2025)");
  script_version("2025-08-29T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-08-29 05:38:41 +0000 (Fri, 29 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7721-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU25\.04");

  script_xref(name:"Advisory-ID", value:"USN-7721-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7721-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure' package(s) announced via the USN-7721-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - ARM64 architecture,
 - PA-RISC architecture,
 - PowerPC architecture,
 - RISC-V architecture,
 - S390 architecture,
 - x86 architecture,
 - Compute Acceleration Framework,
 - Ublk userspace block driver,
 - Bluetooth drivers,
 - Buffer Sharing and Synchronization framework,
 - DMA engine subsystem,
 - ARM SCMI message protocol,
 - GPU drivers,
 - HID subsystem,
 - IIO ADC drivers,
 - IIO subsystem,
 - InfiniBand drivers,
 - Input Device core drivers,
 - IOMMU subsystem,
 - IRQ chip drivers,
 - Multiple devices driver,
 - Network drivers,
 - Mellanox network drivers,
 - PCI subsystem,
 - PHY drivers,
 - PTP clock framework,
 - Voltage and Current Regulator drivers,
 - SPI subsystem,
 - VideoCore services drivers,
 - USB Type-C Connector System Software Interface driver,
 - Xen hypervisor drivers,
 - BTRFS file system,
 - EROFS file system,
 - Network file system (NFS) client,
 - File systems infrastructure,
 - SMB network file system,
 - Network traffic control,
 - eXpress Data Path,
 - Universal MIDI packet (UMP) support module,
 - io_uring subsystem,
 - Kernel command line parsing driver,
 - Scheduler infrastructure,
 - Tracing infrastructure,
 - Memory management,
 - Networking core,
 - IPv4 networking,
 - IPv6 networking,
 - MAC80211 subsystem,
 - Management Component Transport Protocol (MCTP),
 - Netfilter,
 - Open vSwitch,
 - TLS protocol,
 - Wireless networking,
 - AMD SoC Alsa drivers,
 - SoC Audio generic drivers,
 - SOF drivers,
(CVE-2025-37959, CVE-2025-37927, CVE-2025-37891, CVE-2025-37906,
CVE-2025-37962, CVE-2025-37972, CVE-2025-37919, CVE-2025-37958,
CVE-2025-37929, CVE-2025-37969, CVE-2025-37949, CVE-2025-37916,
CVE-2025-38027, CVE-2025-37968, CVE-2025-37931, CVE-2025-37923,
CVE-2025-37918, CVE-2025-37998, CVE-2025-37907, CVE-2025-37894,
CVE-2025-38028, CVE-2025-37915, CVE-2025-38008, CVE-2025-37946,
CVE-2025-38020, CVE-2025-37926, CVE-2025-37950, CVE-2025-38216,
CVE-2025-37973, CVE-2025-38014, CVE-2025-37963, CVE-2025-38009,
CVE-2025-38010, CVE-2025-37971, CVE-2025-38012, CVE-2025-38094,
CVE-2025-37955, CVE-2025-37904, CVE-2025-38095, CVE-2025-37951,
CVE-2025-37964, CVE-2025-37901, CVE-2025-37956, CVE-2025-38016,
CVE-2025-37960, CVE-2025-37898, CVE-2025-37992, CVE-2025-38006,
CVE-2025-37993, CVE-2025-37921, CVE-2025-38007, CVE-2025-37930,
CVE-2025-37895, CVE-2025-37897, CVE-2025-37933, CVE-2025-37899,
CVE-2025-37967, CVE-2025-38019, CVE-2025-37966, CVE-2025-37961,
CVE-2025-37934, CVE-2025-37952, CVE-2025-37994, CVE-2025-37914,
CVE-2025-38083, CVE-2025-37970, CVE-2025-37965, CVE-2025-38025,
CVE-2025-38023, CVE-2025-38015, CVE-2025-37911, CVE-2025-38056,
CVE-2025-37995, CVE-2025-37991, CVE-2025-37920, CVE-2025-38011,
CVE-2025-37910, CVE-2025-37924, CVE-2025-37996, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-azure' package(s) on Ubuntu 25.04.");

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

if(release == "UBUNTU25.04") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.14.0-1010-azure", ver:"6.14.0-1010.10", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"6.14.0-1010.10", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-6.14", ver:"6.14.0-1010.10", rls:"UBUNTU25.04"))) {
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
