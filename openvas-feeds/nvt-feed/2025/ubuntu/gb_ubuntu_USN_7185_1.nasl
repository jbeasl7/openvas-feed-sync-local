# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7185.1");
  script_cve_id("CVE-2021-47076", "CVE-2021-47082", "CVE-2021-47501", "CVE-2022-36402", "CVE-2023-35827", "CVE-2023-52486", "CVE-2023-52507", "CVE-2023-52509", "CVE-2023-52594", "CVE-2024-26625", "CVE-2024-26777", "CVE-2024-26921", "CVE-2024-35847", "CVE-2024-35886", "CVE-2024-36004", "CVE-2024-36270", "CVE-2024-36941", "CVE-2024-36946", "CVE-2024-36968", "CVE-2024-38619", "CVE-2024-38633", "CVE-2024-39301", "CVE-2024-40912", "CVE-2024-40959", "CVE-2024-42077", "CVE-2024-42090", "CVE-2024-42101", "CVE-2024-42153", "CVE-2024-42156", "CVE-2024-43856", "CVE-2024-43884", "CVE-2024-44944", "CVE-2024-44947", "CVE-2024-45006", "CVE-2024-45021", "CVE-2024-49967", "CVE-2024-50264", "CVE-2024-53057");
  script_tag(name:"creation_date", value:"2025-01-07 04:09:04 +0000 (Tue, 07 Jan 2025)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-22 17:55:23 +0000 (Fri, 22 Nov 2024)");

  script_name("Ubuntu: Security Advisory (USN-7185-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7185-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7185-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-hwe, linux-gcp, linux-gcp-4.15, linux-hwe, linux-kvm, linux-oracle' package(s) announced via the USN-7185-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ziming Zhang discovered that the VMware Virtual GPU DRM driver in the Linux
kernel contained an integer overflow vulnerability. A local attacker could
use this to cause a denial of service (system crash). (CVE-2022-36402)

Zheng Wang discovered a use-after-free in the Renesas Ethernet AVB driver
in the Linux kernel during device removal. A privileged attacker could use
this to cause a denial of service (system crash). (CVE-2023-35827)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - GPU drivers,
 - I2C subsystem,
 - InfiniBand drivers,
 - IRQ chip drivers,
 - Network drivers,
 - Pin controllers subsystem,
 - S/390 drivers,
 - TTY drivers,
 - USB Host Controller drivers,
 - USB Mass Storage drivers,
 - Framebuffer layer,
 - Ext4 file system,
 - File systems infrastructure,
 - Bluetooth subsystem,
 - DMA mapping infrastructure,
 - Memory management,
 - 9P file system network protocol,
 - IPv4 networking,
 - IPv6 networking,
 - Logical Link layer,
 - MAC80211 subsystem,
 - Netfilter,
 - NFC subsystem,
 - Phonet protocol,
 - Network traffic control,
 - VMware vSockets driver,
 - Wireless networking,
(CVE-2024-42090, CVE-2024-42156, CVE-2021-47082, CVE-2024-26921,
CVE-2023-52594, CVE-2024-36968, CVE-2024-38633, CVE-2024-42077,
CVE-2021-47076, CVE-2021-47501, CVE-2023-52507, CVE-2024-42153,
CVE-2024-39301, CVE-2024-36946, CVE-2024-43884, CVE-2023-52509,
CVE-2024-36004, CVE-2023-52486, CVE-2024-50264, CVE-2024-45006,
CVE-2024-36941, CVE-2024-43856, CVE-2024-40912, CVE-2024-49967,
CVE-2024-53057, CVE-2024-26777, CVE-2024-36270, CVE-2024-26625,
CVE-2024-45021, CVE-2024-35886, CVE-2024-44947, CVE-2024-44944,
CVE-2024-35847, CVE-2024-40959, CVE-2024-42101, CVE-2024-38619)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-hwe, linux-gcp, linux-gcp-4.15, linux-hwe, linux-kvm, linux-oracle' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1138-oracle", ver:"4.15.0-1138.149~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1169-gcp", ver:"4.15.0-1169.186~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1176-aws", ver:"4.15.0-1176.189~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-232-generic", ver:"4.15.0-232.244~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-232-lowlatency", ver:"4.15.0-232.244~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-hwe", ver:"4.15.0.1176.189~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"4.15.0.1169.186~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-16.04", ver:"4.15.0.232.244~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"4.15.0.1169.186~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-16.04", ver:"4.15.0.232.244~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem", ver:"4.15.0.232.244~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"4.15.0.1138.149~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-16.04", ver:"4.15.0.232.244~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1138-oracle", ver:"4.15.0-1138.149", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1159-kvm", ver:"4.15.0-1159.164", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1169-gcp", ver:"4.15.0-1169.186", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1176-aws", ver:"4.15.0-1176.189", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-232-generic", ver:"4.15.0-232.244", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-232-lowlatency", ver:"4.15.0-232.244", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-lts-18.04", ver:"4.15.0.1176.174", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-lts-18.04", ver:"4.15.0.1169.182", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.15.0.232.216", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"4.15.0.1159.150", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.15.0.232.216", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-lts-18.04", ver:"4.15.0.1138.143", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"4.15.0.232.216", rls:"UBUNTU18.04 LTS"))) {
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
