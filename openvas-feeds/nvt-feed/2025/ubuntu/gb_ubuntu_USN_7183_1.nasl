# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7183.1");
  script_cve_id("CVE-2020-12351", "CVE-2020-12352", "CVE-2020-24490", "CVE-2021-47086", "CVE-2021-47118", "CVE-2021-47501", "CVE-2022-36402", "CVE-2023-35827", "CVE-2023-52507", "CVE-2023-52509", "CVE-2023-52594", "CVE-2024-26625", "CVE-2024-26777", "CVE-2024-35886", "CVE-2024-36270", "CVE-2024-36941", "CVE-2024-36946", "CVE-2024-36968", "CVE-2024-38619", "CVE-2024-38633", "CVE-2024-39301", "CVE-2024-40912", "CVE-2024-40959", "CVE-2024-42090", "CVE-2024-42101", "CVE-2024-42153", "CVE-2024-43856", "CVE-2024-43884", "CVE-2024-44944", "CVE-2024-44947", "CVE-2024-45021", "CVE-2024-49967", "CVE-2024-53057");
  script_tag(name:"creation_date", value:"2025-01-07 04:09:04 +0000 (Tue, 07 Jan 2025)");
  script_version("2025-01-07T06:11:07+0000");
  script_tag(name:"last_modification", value:"2025-01-07 06:11:07 +0000 (Tue, 07 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-30 17:14:46 +0000 (Mon, 30 Nov 2020)");

  script_name("Ubuntu: Security Advisory (USN-7183-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7183-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7183-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-lts-xenial' package(s) announced via the USN-7183-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Andy Nguyen discovered that the Bluetooth L2CAP implementation in the Linux
kernel contained a type-confusion error. A physically proximate remote
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2020-12351)

Andy Nguyen discovered that the Bluetooth A2MP implementation in the Linux
kernel did not properly initialize memory in some situations. A physically
proximate remote attacker could use this to expose sensitive information
(kernel memory). (CVE-2020-12352)

Andy Nguyen discovered that the Bluetooth HCI event packet parser in the
Linux kernel did not properly handle event advertisements of certain sizes,
leading to a heap-based buffer overflow. A physically proximate remote
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2020-24490)

Ziming Zhang discovered that the VMware Virtual GPU DRM driver in the Linux
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
 - Network drivers,
 - Pin controllers subsystem,
 - TTY drivers,
 - USB Mass Storage drivers,
 - Framebuffer layer,
 - Ext4 file system,
 - File systems infrastructure,
 - Bluetooth subsystem,
 - Kernel init infrastructure,
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
 - Wireless networking,
(CVE-2024-44947, CVE-2023-52594, CVE-2024-35886, CVE-2024-38633,
CVE-2023-52509, CVE-2024-26625, CVE-2024-36946, CVE-2024-45021,
CVE-2024-36270, CVE-2021-47118, CVE-2024-43884, CVE-2024-36941,
CVE-2024-38619, CVE-2021-47501, CVE-2024-49967, CVE-2024-42090,
CVE-2024-40912, CVE-2024-36968, CVE-2024-53057, CVE-2023-52507,
CVE-2024-42101, CVE-2021-47086, CVE-2024-42153, CVE-2024-40959,
CVE-2024-26777, CVE-2024-44944, CVE-2024-43856, CVE-2024-39301)");

  script_tag(name:"affected", value:"'linux, linux-lts-xenial' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-262-generic", ver:"4.4.0-262.296~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-262-lowlatency", ver:"4.4.0-262.296~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lts-xenial", ver:"4.4.0.262.296~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-lts-xenial", ver:"4.4.0.262.296~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-lts-xenial", ver:"4.4.0.262.296~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-262-generic", ver:"4.4.0-262.296", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-262-lowlatency", ver:"4.4.0-262.296", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.4.0.262.268", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lts-xenial", ver:"4.4.0.262.268", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.4.0.262.268", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-lts-xenial", ver:"4.4.0.262.268", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"4.4.0.262.268", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-lts-xenial", ver:"4.4.0.262.268", rls:"UBUNTU16.04 LTS"))) {
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
