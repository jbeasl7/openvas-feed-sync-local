# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7004.1");
  script_cve_id("CVE-2022-48772", "CVE-2023-52884", "CVE-2024-23848", "CVE-2024-31076", "CVE-2024-32936", "CVE-2024-33619", "CVE-2024-33621", "CVE-2024-33847", "CVE-2024-34027", "CVE-2024-34030", "CVE-2024-34777", "CVE-2024-35247", "CVE-2024-36015", "CVE-2024-36244", "CVE-2024-36270", "CVE-2024-36281", "CVE-2024-36286", "CVE-2024-36288", "CVE-2024-36477", "CVE-2024-36478", "CVE-2024-36479", "CVE-2024-36481", "CVE-2024-36484", "CVE-2024-36489", "CVE-2024-36971", "CVE-2024-36972", "CVE-2024-36973", "CVE-2024-36974", "CVE-2024-36978", "CVE-2024-37021", "CVE-2024-37026", "CVE-2024-37078", "CVE-2024-37354", "CVE-2024-37356", "CVE-2024-38306", "CVE-2024-38381", "CVE-2024-38384", "CVE-2024-38385", "CVE-2024-38388", "CVE-2024-38390", "CVE-2024-38618", "CVE-2024-38619", "CVE-2024-38621", "CVE-2024-38622", "CVE-2024-38623", "CVE-2024-38624", "CVE-2024-38625", "CVE-2024-38627", "CVE-2024-38628", "CVE-2024-38629", "CVE-2024-38630", "CVE-2024-38632", "CVE-2024-38633", "CVE-2024-38634", "CVE-2024-38635", "CVE-2024-38636", "CVE-2024-38637", "CVE-2024-38659", "CVE-2024-38661", "CVE-2024-38662", "CVE-2024-38663", "CVE-2024-38664", "CVE-2024-38667", "CVE-2024-38780", "CVE-2024-39276", "CVE-2024-39277", "CVE-2024-39291", "CVE-2024-39296", "CVE-2024-39298", "CVE-2024-39301", "CVE-2024-39371", "CVE-2024-39461", "CVE-2024-39462", "CVE-2024-39463", "CVE-2024-39464", "CVE-2024-39465", "CVE-2024-39466", "CVE-2024-39467", "CVE-2024-39468", "CVE-2024-39469", "CVE-2024-39470", "CVE-2024-39471", "CVE-2024-39473", "CVE-2024-39474", "CVE-2024-39475", "CVE-2024-39478", "CVE-2024-39479", "CVE-2024-39480", "CVE-2024-39481", "CVE-2024-39483", "CVE-2024-39485", "CVE-2024-39488", "CVE-2024-39489", "CVE-2024-39490", "CVE-2024-39491", "CVE-2024-39492", "CVE-2024-39493", "CVE-2024-39494", "CVE-2024-39495", "CVE-2024-39496", "CVE-2024-39497", "CVE-2024-39498", "CVE-2024-39499", "CVE-2024-39500", "CVE-2024-39501", "CVE-2024-39502", "CVE-2024-39503", "CVE-2024-39504", "CVE-2024-39505", "CVE-2024-39506", "CVE-2024-39507", "CVE-2024-39508", "CVE-2024-39509", "CVE-2024-39510", "CVE-2024-40899", "CVE-2024-40900", "CVE-2024-40901", "CVE-2024-40902", "CVE-2024-40903", "CVE-2024-40904", "CVE-2024-40905", "CVE-2024-40906", "CVE-2024-40908", "CVE-2024-40909", "CVE-2024-40910", "CVE-2024-40911", "CVE-2024-40912", "CVE-2024-40913", "CVE-2024-40914", "CVE-2024-40915", "CVE-2024-40916", "CVE-2024-40917", "CVE-2024-40918", "CVE-2024-40919", "CVE-2024-40920", "CVE-2024-40921", "CVE-2024-40922", "CVE-2024-40923", "CVE-2024-40924", "CVE-2024-40925", "CVE-2024-40926", "CVE-2024-40927", "CVE-2024-40928", "CVE-2024-40929", "CVE-2024-40930", "CVE-2024-40931", "CVE-2024-40932", "CVE-2024-40933", "CVE-2024-40934", "CVE-2024-40935", "CVE-2024-40936", "CVE-2024-40937", "CVE-2024-40938", "CVE-2024-40939", "CVE-2024-40940", "CVE-2024-40941", "CVE-2024-40942", "CVE-2024-40943", "CVE-2024-40944", "CVE-2024-40945", "CVE-2024-40947", "CVE-2024-40948", "CVE-2024-40949", "CVE-2024-40951", "CVE-2024-40952", "CVE-2024-40953", "CVE-2024-40954", "CVE-2024-40955", "CVE-2024-40956", "CVE-2024-40957", "CVE-2024-40958", "CVE-2024-40959", "CVE-2024-40960", "CVE-2024-40961", "CVE-2024-40962", "CVE-2024-40963", "CVE-2024-40964", "CVE-2024-40965", "CVE-2024-40966", "CVE-2024-40967", "CVE-2024-40968", "CVE-2024-40969", "CVE-2024-40970", "CVE-2024-40971", "CVE-2024-40972", "CVE-2024-40973", "CVE-2024-40974", "CVE-2024-40975", "CVE-2024-40976", "CVE-2024-40977", "CVE-2024-40978", "CVE-2024-40979", "CVE-2024-40980", "CVE-2024-40981", "CVE-2024-40982", "CVE-2024-40983", "CVE-2024-40984", "CVE-2024-40985", "CVE-2024-40986", "CVE-2024-40987", "CVE-2024-40988", "CVE-2024-40989", "CVE-2024-40990", "CVE-2024-40992", "CVE-2024-40994", "CVE-2024-40995", "CVE-2024-40996", "CVE-2024-40997", "CVE-2024-40998", "CVE-2024-40999", "CVE-2024-41000", "CVE-2024-41001", "CVE-2024-41002", "CVE-2024-41003", "CVE-2024-41004", "CVE-2024-41005", "CVE-2024-41006", "CVE-2024-41040", "CVE-2024-42078", "CVE-2024-42148", "CVE-2024-42270");
  script_tag(name:"creation_date", value:"2024-09-13 04:07:39 +0000 (Fri, 13 Sep 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-05 17:46:27 +0000 (Thu, 05 Sep 2024)");

  script_name("Ubuntu: Security Advisory (USN-7004-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU24\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7004-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7004-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure' package(s) announced via the USN-7004-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chenyuan Yang discovered that the CEC driver driver in the Linux kernel
contained a use-after-free vulnerability. A local attacker could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2024-23848)

It was discovered that the JFS file system contained an out-of-bounds read
vulnerability when printing xattr debug information. A local attacker could
use this to cause a denial of service (system crash). (CVE-2024-40902)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - ARM64 architecture,
 - MIPS architecture,
 - PA-RISC architecture,
 - PowerPC architecture,
 - RISC-V architecture,
 - x86 architecture,
 - Block layer subsystem,
 - ACPI drivers,
 - Drivers core,
 - Null block device driver,
 - Character device driver,
 - TPM device driver,
 - Clock framework and drivers,
 - CPU frequency scaling framework,
 - Hardware crypto device drivers,
 - CXL (Compute Express Link) drivers,
 - Buffer Sharing and Synchronization framework,
 - DMA engine subsystem,
 - EFI core,
 - FPGA Framework,
 - GPU drivers,
 - Greybus drivers,
 - HID subsystem,
 - HW tracing,
 - I2C subsystem,
 - IIO subsystem,
 - InfiniBand drivers,
 - Input Device (Mouse) drivers,
 - Mailbox framework,
 - Media drivers,
 - Microchip PCI driver,
 - VMware VMCI Driver,
 - Network drivers,
 - PCI subsystem,
 - x86 platform drivers,
 - PTP clock framework,
 - S/390 drivers,
 - SCSI drivers,
 - SoundWire subsystem,
 - Sonic Silicon Backplane drivers,
 - Greybus lights staging drivers,
 - Thermal drivers,
 - TTY drivers,
 - USB subsystem,
 - VFIO drivers,
 - Framebuffer layer,
 - Watchdog drivers,
 - 9P distributed file system,
 - BTRFS file system,
 - File systems infrastructure,
 - Ext4 file system,
 - F2FS file system,
 - JFS file system,
 - Network file system server daemon,
 - NILFS2 file system,
 - NTFS3 file system,
 - SMB network file system,
 - Tracing file system,
 - IOMMU subsystem,
 - Tracing infrastructure,
 - io_uring subsystem,
 - Core kernel,
 - BPF subsystem,
 - Kernel debugger infrastructure,
 - DMA mapping infrastructure,
 - IRQ subsystem,
 - Memory management,
 - 9P file system network protocol,
 - Amateur Radio drivers,
 - B.A.T.M.A.N. meshing protocol,
 - Ethernet bridge,
 - Networking core,
 - Ethtool driver,
 - IPv4 networking,
 - IPv6 networking,
 - MAC80211 subsystem,
 - Multipath TCP,
 - Netfilter,
 - NET/ROM layer,
 - NFC subsystem,
 - Network traffic control,
 - Sun RPC protocol,
 - TIPC protocol,
 - TLS protocol,
 - Unix domain sockets,
 - Wireless networking,
 - XFRM subsystem,
 - AppArmor security module,
 - Integrity Measurement Architecture(IMA) framework,
 - Landlock security,
 - Linux Security Modules (LSM) Framework,
 - SELinux security module,
 - Simplified Mandatory Access Control Kernel framework,
 - ALSA ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-azure' package(s) on Ubuntu 24.04.");

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

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1014-azure", ver:"6.8.0-1014.16", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1014-azure-fde", ver:"6.8.0-1014.16", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"6.8.0-1014.16", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-fde", ver:"6.8.0-1014.16", rls:"UBUNTU24.04 LTS"))) {
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
