# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7703.3");
  script_cve_id("CVE-2024-52559", "CVE-2024-54456", "CVE-2024-54458", "CVE-2024-57834", "CVE-2024-57977", "CVE-2024-58020", "CVE-2024-58086", "CVE-2024-58088", "CVE-2024-58093", "CVE-2025-21704", "CVE-2025-21706", "CVE-2025-21712", "CVE-2025-21746", "CVE-2025-21758", "CVE-2025-21759", "CVE-2025-21760", "CVE-2025-21761", "CVE-2025-21762", "CVE-2025-21763", "CVE-2025-21764", "CVE-2025-21765", "CVE-2025-21766", "CVE-2025-21767", "CVE-2025-21768", "CVE-2025-21772", "CVE-2025-21773", "CVE-2025-21775", "CVE-2025-21776", "CVE-2025-21779", "CVE-2025-21780", "CVE-2025-21781", "CVE-2025-21782", "CVE-2025-21783", "CVE-2025-21784", "CVE-2025-21785", "CVE-2025-21786", "CVE-2025-21787", "CVE-2025-21790", "CVE-2025-21791", "CVE-2025-21792", "CVE-2025-21793", "CVE-2025-21795", "CVE-2025-21796", "CVE-2025-21821", "CVE-2025-21823", "CVE-2025-21835", "CVE-2025-21836", "CVE-2025-21838", "CVE-2025-21839", "CVE-2025-21844", "CVE-2025-21846", "CVE-2025-21847", "CVE-2025-21848", "CVE-2025-21853", "CVE-2025-21854", "CVE-2025-21855", "CVE-2025-21856", "CVE-2025-21857", "CVE-2025-21858", "CVE-2025-21859", "CVE-2025-21861", "CVE-2025-21862", "CVE-2025-21863", "CVE-2025-21864", "CVE-2025-21866", "CVE-2025-21867", "CVE-2025-21868", "CVE-2025-21869", "CVE-2025-21870", "CVE-2025-21871");
  script_tag(name:"creation_date", value:"2025-08-22 04:04:19 +0000 (Fri, 22 Aug 2025)");
  script_version("2025-08-22T05:39:46+0000");
  script_tag(name:"last_modification", value:"2025-08-22 05:39:46 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-13 21:13:44 +0000 (Thu, 13 Mar 2025)");

  script_name("Ubuntu: Security Advisory (USN-7703-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7703-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7703-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-oracle, linux-oracle-6.8' package(s) announced via the USN-7703-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - ARM64 architecture,
 - PowerPC architecture,
 - x86 architecture,
 - Block layer subsystem,
 - GPIO subsystem,
 - GPU drivers,
 - HID subsystem,
 - Input Device (Mouse) drivers,
 - Multiple devices driver,
 - Media drivers,
 - Network drivers,
 - PCI subsystem,
 - S/390 drivers,
 - SPI subsystem,
 - Trusted Execution Environment drivers,
 - UFS subsystem,
 - USB Device Class drivers,
 - USB core drivers,
 - USB Gadget drivers,
 - Framebuffer layer,
 - Network file system (NFS) client,
 - Network file system (NFS) server daemon,
 - File systems infrastructure,
 - SMB network file system,
 - Networking core,
 - L3 Master device support module,
 - TCP network protocol,
 - io_uring subsystem,
 - Process Accounting mechanism,
 - BPF subsystem,
 - Timer subsystem,
 - Workqueue subsystem,
 - Memory management,
 - Amateur Radio drivers,
 - B.A.T.M.A.N. meshing protocol,
 - IPv4 networking,
 - IPv6 networking,
 - Multipath TCP,
 - Open vSwitch,
 - Network traffic control,
 - SOF drivers,
(CVE-2025-21776, CVE-2025-21768, CVE-2025-21848, CVE-2025-21855,
CVE-2025-21791, CVE-2025-21838, CVE-2025-21762, CVE-2025-21846,
CVE-2025-21765, CVE-2025-21869, CVE-2025-21783, CVE-2025-21868,
CVE-2025-21857, CVE-2025-21773, CVE-2024-54458, CVE-2025-21871,
CVE-2025-21763, CVE-2024-58088, CVE-2025-21835, CVE-2025-21793,
CVE-2025-21867, CVE-2025-21784, CVE-2025-21839, CVE-2025-21786,
CVE-2025-21764, CVE-2025-21761, CVE-2025-21767, CVE-2024-58020,
CVE-2025-21847, CVE-2025-21792, CVE-2025-21785, CVE-2025-21863,
CVE-2025-21854, CVE-2025-21704, CVE-2024-52559, CVE-2025-21775,
CVE-2025-21758, CVE-2025-21858, CVE-2025-21866, CVE-2025-21870,
CVE-2024-57977, CVE-2024-54456, CVE-2025-21759, CVE-2025-21781,
CVE-2025-21760, CVE-2025-21706, CVE-2024-57834, CVE-2025-21712,
CVE-2025-21864, CVE-2025-21780, CVE-2025-21790, CVE-2025-21856,
CVE-2025-21796, CVE-2025-21859, CVE-2025-21782, CVE-2024-58093,
CVE-2025-21844, CVE-2025-21795, CVE-2025-21823, CVE-2025-21853,
CVE-2025-21772, CVE-2025-21746, CVE-2025-21821, CVE-2024-58086,
CVE-2025-21787, CVE-2025-21836, CVE-2025-21861, CVE-2025-21766,
CVE-2025-21862, CVE-2025-21779)");

  script_tag(name:"affected", value:"'linux-oracle, linux-oracle-6.8' package(s) on Ubuntu 22.04, Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1032-oracle", ver:"6.8.0-1032.33~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1032-oracle-64k", ver:"6.8.0-1032.33~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"6.8.0-1032.33~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-6.8", ver:"6.8.0-1032.33~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-64k", ver:"6.8.0-1032.33~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-64k-6.8", ver:"6.8.0-1032.33~22.04.1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1032-oracle", ver:"6.8.0-1032.33", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1032-oracle-64k", ver:"6.8.0-1032.33", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-6.8", ver:"6.8.0-1032.33", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-64k-6.8", ver:"6.8.0-1032.33", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-64k-lts-24.04", ver:"6.8.0-1032.33", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-lts-24.04", ver:"6.8.0-1032.33", rls:"UBUNTU24.04 LTS"))) {
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
