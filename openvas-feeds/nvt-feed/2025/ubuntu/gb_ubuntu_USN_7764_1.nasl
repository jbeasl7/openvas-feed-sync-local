# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7764.1");
  script_cve_id("CVE-2024-58090", "CVE-2025-21872", "CVE-2025-21873", "CVE-2025-21875", "CVE-2025-21877", "CVE-2025-21878", "CVE-2025-21880", "CVE-2025-21881", "CVE-2025-21883", "CVE-2025-21885", "CVE-2025-21888", "CVE-2025-21889", "CVE-2025-21890", "CVE-2025-21891", "CVE-2025-21892", "CVE-2025-21894", "CVE-2025-21895", "CVE-2025-21898", "CVE-2025-21899", "CVE-2025-21903", "CVE-2025-21904", "CVE-2025-21905", "CVE-2025-21908", "CVE-2025-21909", "CVE-2025-21910", "CVE-2025-21911", "CVE-2025-21912", "CVE-2025-21913", "CVE-2025-21914", "CVE-2025-21915", "CVE-2025-21916", "CVE-2025-21917", "CVE-2025-21918", "CVE-2025-21919", "CVE-2025-21920", "CVE-2025-21922", "CVE-2025-21924", "CVE-2025-21925", "CVE-2025-21926", "CVE-2025-21927", "CVE-2025-21928", "CVE-2025-21929", "CVE-2025-21930", "CVE-2025-21934", "CVE-2025-21935", "CVE-2025-21936", "CVE-2025-21937", "CVE-2025-21941", "CVE-2025-21944", "CVE-2025-21945", "CVE-2025-21946", "CVE-2025-21947", "CVE-2025-21948", "CVE-2025-21950", "CVE-2025-21951", "CVE-2025-21955", "CVE-2025-21956", "CVE-2025-21957", "CVE-2025-21959", "CVE-2025-21960", "CVE-2025-21961", "CVE-2025-21962", "CVE-2025-21963", "CVE-2025-21964", "CVE-2025-21966", "CVE-2025-21967", "CVE-2025-21968", "CVE-2025-21969", "CVE-2025-21970", "CVE-2025-21972", "CVE-2025-21975", "CVE-2025-21976", "CVE-2025-21977", "CVE-2025-21978", "CVE-2025-21979", "CVE-2025-21980", "CVE-2025-21981", "CVE-2025-21982", "CVE-2025-21986", "CVE-2025-21991", "CVE-2025-21992", "CVE-2025-21994", "CVE-2025-21995", "CVE-2025-21996", "CVE-2025-21997", "CVE-2025-21999", "CVE-2025-22001", "CVE-2025-22003", "CVE-2025-22004", "CVE-2025-22005", "CVE-2025-22007", "CVE-2025-22008", "CVE-2025-22009", "CVE-2025-22010", "CVE-2025-22011", "CVE-2025-22013", "CVE-2025-22014", "CVE-2025-22015", "CVE-2025-22016", "CVE-2025-22017", "CVE-2025-22047", "CVE-2025-37889", "CVE-2025-38569");
  script_tag(name:"creation_date", value:"2025-09-25 04:04:35 +0000 (Thu, 25 Sep 2025)");
  script_version("2025-09-25T05:39:09+0000");
  script_tag(name:"last_modification", value:"2025-09-25 05:39:09 +0000 (Thu, 25 Sep 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-10 13:24:35 +0000 (Thu, 10 Apr 2025)");

  script_name("Ubuntu: Security Advisory (USN-7764-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7764-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7764-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-gcp, linux-gke, linux-gkeop, linux-lowlatency, linux-lowlatency-hwe-6.8' package(s) announced via the USN-7764-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - ARM32 architecture,
 - ARM64 architecture,
 - x86 architecture,
 - Compute Acceleration Framework,
 - Bus devices,
 - AMD CDX bus driver,
 - DPLL subsystem,
 - EFI core,
 - GPIO subsystem,
 - GPU drivers,
 - HID subsystem,
 - I2C subsystem,
 - InfiniBand drivers,
 - Multiple devices driver,
 - Network drivers,
 - Mellanox network drivers,
 - NVME drivers,
 - Pin controllers subsystem,
 - RapidIO drivers,
 - Voltage and Current Regulator drivers,
 - SCSI subsystem,
 - SLIMbus drivers,
 - QCOM SoC drivers,
 - UFS subsystem,
 - USB DSL drivers,
 - Renesas USBHS Controller drivers,
 - USB Type-C Connector System Software Interface driver,
 - Framebuffer layer,
 - ACRN Hypervisor Service Module driver,
 - Network file system (NFS) client,
 - Proc file system,
 - SMB network file system,
 - Memory Management,
 - Scheduler infrastructure,
 - SoC audio core drivers,
 - Perf events,
 - Tracing infrastructure,
 - Memory management,
 - 802.1Q VLAN protocol,
 - Asynchronous Transfer Mode (ATM) subsystem,
 - Bluetooth subsystem,
 - Devlink API,
 - IPv4 networking,
 - IPv6 networking,
 - Logical Link layer,
 - Management Component Transport Protocol (MCTP),
 - Multipath TCP,
 - Netfilter,
 - Network traffic control,
 - Switch device API,
 - Wireless networking,
 - eXpress Data Path,
(CVE-2025-22008, CVE-2025-21872, CVE-2025-21945, CVE-2025-37889,
CVE-2025-21997, CVE-2025-21935, CVE-2025-21986, CVE-2025-21890,
CVE-2025-21925, CVE-2024-58090, CVE-2025-38569, CVE-2025-21911,
CVE-2025-21957, CVE-2025-21891, CVE-2025-21924, CVE-2025-21956,
CVE-2025-21994, CVE-2025-22013, CVE-2025-21964, CVE-2025-21909,
CVE-2025-21888, CVE-2025-21918, CVE-2025-21981, CVE-2025-21966,
CVE-2025-22011, CVE-2025-21877, CVE-2025-21913, CVE-2025-21895,
CVE-2025-21929, CVE-2025-22010, CVE-2025-21992, CVE-2025-21930,
CVE-2025-21982, CVE-2025-21894, CVE-2025-21934, CVE-2025-21873,
CVE-2025-21914, CVE-2025-21941, CVE-2025-21962, CVE-2025-22014,
CVE-2025-21905, CVE-2025-21908, CVE-2025-21898, CVE-2025-21878,
CVE-2025-22009, CVE-2025-21961, CVE-2025-22015, CVE-2025-21883,
CVE-2025-21916, CVE-2025-22016, CVE-2025-21936, CVE-2025-21947,
CVE-2025-21927, CVE-2025-22004, CVE-2025-21926, CVE-2025-21969,
CVE-2025-21976, CVE-2025-21912, CVE-2025-21920, CVE-2025-21951,
CVE-2025-22005, CVE-2025-21978, CVE-2025-21975, CVE-2025-22007,
CVE-2025-21928, CVE-2025-21968, CVE-2025-21963, CVE-2025-21977,
CVE-2025-21915, CVE-2025-21980, CVE-2025-22047, CVE-2025-21972,
CVE-2025-21892, CVE-2025-22003, CVE-2025-21979, CVE-2025-21944,
CVE-2025-21880, CVE-2025-21899, CVE-2025-21995, CVE-2025-22017,
CVE-2025-21946, CVE-2025-22001, CVE-2025-21904, CVE-2025-21881,
CVE-2025-21917, CVE-2025-21970, CVE-2025-21889, CVE-2025-21922,
CVE-2025-21875, CVE-2025-21919, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-gcp, linux-gke, linux-gkeop, linux-lowlatency, linux-lowlatency-hwe-6.8' package(s) on Ubuntu 22.04, Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-84-lowlatency", ver:"6.8.0-84.84.1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-84-lowlatency-64k", ver:"6.8.0-84.84.1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-6.8", ver:"6.8.0-84.84.1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k-6.8", ver:"6.8.0-84.84.1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k-hwe-22.04", ver:"6.8.0-84.84.1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-22.04", ver:"6.8.0-84.84.1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1023-gkeop", ver:"6.8.0-1023.25", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1036-gke", ver:"6.8.0-1036.40", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1036-gke-64k", ver:"6.8.0-1036.40", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1039-aws", ver:"6.8.0-1039.41", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1039-aws-64k", ver:"6.8.0-1039.41", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1040-gcp", ver:"6.8.0-1040.42", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1040-gcp-64k", ver:"6.8.0-1040.42", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-84-generic", ver:"6.8.0-84.84", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-84-generic-64k", ver:"6.8.0-84.84", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-84-lowlatency", ver:"6.8.0-84.84.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-84-lowlatency-64k", ver:"6.8.0-84.84.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-6.8", ver:"6.8.0-1039.41", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-64k-6.8", ver:"6.8.0-1039.41", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-64k-lts-24.04", ver:"6.8.0-1039.41", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-lts-24.04", ver:"6.8.0-1039.41", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-6.8", ver:"6.8.0-1040.42", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-64k-6.8", ver:"6.8.0-1040.42", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-64k-lts-24.04", ver:"6.8.0-1040.42", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-lts-24.04", ver:"6.8.0-1040.42", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"6.8.0-84.84", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-6.8", ver:"6.8.0-84.84", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k", ver:"6.8.0-84.84", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k-6.8", ver:"6.8.0-84.84", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"6.8.0-84.84", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"6.8.0-1036.40", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke-6.8", ver:"6.8.0-1036.40", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke-64k", ver:"6.8.0-1036.40", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke-64k-6.8", ver:"6.8.0-1036.40", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop", ver:"6.8.0-1023.25", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop-6.8", ver:"6.8.0-1023.25", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"6.8.0-84.84", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"6.8.0-84.84.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-6.8", ver:"6.8.0-84.84.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k", ver:"6.8.0-84.84.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k-6.8", ver:"6.8.0-84.84.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"6.8.0-84.84", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-6.8", ver:"6.8.0-84.84", rls:"UBUNTU24.04 LTS"))) {
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
