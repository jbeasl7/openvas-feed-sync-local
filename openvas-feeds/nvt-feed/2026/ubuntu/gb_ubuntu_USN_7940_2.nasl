# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.7940.2");
  script_cve_id("CVE-2023-53034", "CVE-2024-58092", "CVE-2025-21729", "CVE-2025-22018", "CVE-2025-22019", "CVE-2025-22020", "CVE-2025-22021", "CVE-2025-22025", "CVE-2025-22027", "CVE-2025-22028", "CVE-2025-22033", "CVE-2025-22035", "CVE-2025-22036", "CVE-2025-22038", "CVE-2025-22039", "CVE-2025-22040", "CVE-2025-22041", "CVE-2025-22042", "CVE-2025-22044", "CVE-2025-22045", "CVE-2025-22047", "CVE-2025-22050", "CVE-2025-22053", "CVE-2025-22054", "CVE-2025-22055", "CVE-2025-22056", "CVE-2025-22057", "CVE-2025-22058", "CVE-2025-22060", "CVE-2025-22062", "CVE-2025-22063", "CVE-2025-22064", "CVE-2025-22065", "CVE-2025-22066", "CVE-2025-22068", "CVE-2025-22070", "CVE-2025-22071", "CVE-2025-22072", "CVE-2025-22073", "CVE-2025-22075", "CVE-2025-22079", "CVE-2025-22080", "CVE-2025-22081", "CVE-2025-22083", "CVE-2025-22086", "CVE-2025-22089", "CVE-2025-22090", "CVE-2025-22095", "CVE-2025-22097", "CVE-2025-23136", "CVE-2025-23138", "CVE-2025-37838", "CVE-2025-37937", "CVE-2025-37958", "CVE-2025-38118", "CVE-2025-38152", "CVE-2025-38227", "CVE-2025-38240", "CVE-2025-38352", "CVE-2025-38575", "CVE-2025-38616", "CVE-2025-38637", "CVE-2025-38666", "CVE-2025-38678", "CVE-2025-39682", "CVE-2025-39728", "CVE-2025-39735", "CVE-2025-39964", "CVE-2025-39993", "CVE-2025-40018", "CVE-2025-40114", "CVE-2025-40157", "CVE-2025-40300");
  script_tag(name:"creation_date", value:"2026-01-12 07:58:38 +0000 (Mon, 12 Jan 2026)");
  script_version("2026-01-13T05:47:36+0000");
  script_tag(name:"last_modification", value:"2026-01-13 05:47:36 +0000 (Tue, 13 Jan 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-29 13:46:29 +0000 (Tue, 29 Apr 2025)");

  script_name("Ubuntu: Security Advisory (USN-7940-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU24\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7940-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7940-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure-nvidia' package(s) announced via the USN-7940-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jean-Claude Graf, Sandro Ruegge, Ali Hajiabadi, and Kaveh Razavi discovered
that the Linux kernel contained insufficient branch predictor isolation
between a guest and a userspace hypervisor for certain processors. This
flaw is known as VMSCAPE. An attacker in a guest VM could possibly use this
to expose sensitive information from the host OS. (CVE-2025-40300)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - ARM64 architecture,
 - PowerPC architecture,
 - x86 architecture,
 - Cryptographic API,
 - ACPI drivers,
 - Ublk userspace block driver,
 - Clock framework and drivers,
 - EDAC drivers,
 - GPU drivers,
 - HSI subsystem,
 - IIO subsystem,
 - InfiniBand drivers,
 - Media drivers,
 - MemoryStick subsystem,
 - Network drivers,
 - NTB driver,
 - PCI subsystem,
 - Remote Processor subsystem,
 - Thermal drivers,
 - Virtio Host (VHOST) subsystem,
 - 9P distributed file system,
 - File systems infrastructure,
 - JFS file system,
 - Network file system (NFS) server daemon,
 - NTFS3 file system,
 - SMB network file system,
 - Memory management,
 - Bluetooth subsystem,
 - RDMA verbs API,
 - Kernel fork() syscall,
 - Timer subsystem,
 - Tracing infrastructure,
 - Watch queue notification mechanism,
 - Appletalk network protocol,
 - Asynchronous Transfer Mode (ATM) subsystem,
 - Networking core,
 - IPv4 networking,
 - IPv6 networking,
 - Netfilter,
 - Network traffic control,
 - SCTP protocol,
 - TLS protocol,
 - SoC Audio for Freescale CPUs drivers,
(CVE-2023-53034, CVE-2024-58092, CVE-2025-21729, CVE-2025-22018,
CVE-2025-22019, CVE-2025-22020, CVE-2025-22021, CVE-2025-22025,
CVE-2025-22027, CVE-2025-22028, CVE-2025-22033, CVE-2025-22035,
CVE-2025-22036, CVE-2025-22038, CVE-2025-22039, CVE-2025-22040,
CVE-2025-22041, CVE-2025-22042, CVE-2025-22044, CVE-2025-22045,
CVE-2025-22047, CVE-2025-22050, CVE-2025-22053, CVE-2025-22054,
CVE-2025-22055, CVE-2025-22056, CVE-2025-22057, CVE-2025-22058,
CVE-2025-22060, CVE-2025-22062, CVE-2025-22063, CVE-2025-22064,
CVE-2025-22065, CVE-2025-22066, CVE-2025-22068, CVE-2025-22070,
CVE-2025-22071, CVE-2025-22072, CVE-2025-22073, CVE-2025-22075,
CVE-2025-22079, CVE-2025-22080, CVE-2025-22081, CVE-2025-22083,
CVE-2025-22086, CVE-2025-22089, CVE-2025-22090, CVE-2025-22095,
CVE-2025-22097, CVE-2025-23136, CVE-2025-23138, CVE-2025-37838,
CVE-2025-37937, CVE-2025-37958, CVE-2025-38118, CVE-2025-38152,
CVE-2025-38227, CVE-2025-38240, CVE-2025-38352, CVE-2025-38575,
CVE-2025-38616, CVE-2025-38637, CVE-2025-38666, CVE-2025-38678,
CVE-2025-39682, CVE-2025-39728, CVE-2025-39735, CVE-2025-39964,
CVE-2025-39993, CVE-2025-40018, CVE-2025-40114, CVE-2025-40157)");

  script_tag(name:"affected", value:"'linux-azure-nvidia' package(s) on Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1029-azure-nvidia", ver:"6.8.0-1029.32", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-nvidia-6.8", ver:"6.8.0-1029.32", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-nvidia-lts-24.04", ver:"6.8.0-1029.32", rls:"UBUNTU24.04 LTS"))) {
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
