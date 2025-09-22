# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6926.2");
  script_cve_id("CVE-2023-46343", "CVE-2023-52435", "CVE-2023-52436", "CVE-2023-52443", "CVE-2023-52444", "CVE-2023-52449", "CVE-2023-52469", "CVE-2023-52620", "CVE-2023-52752", "CVE-2024-24857", "CVE-2024-24858", "CVE-2024-24859", "CVE-2024-25739", "CVE-2024-25744", "CVE-2024-26840", "CVE-2024-26857", "CVE-2024-26882", "CVE-2024-26884", "CVE-2024-26886", "CVE-2024-26901", "CVE-2024-26923", "CVE-2024-26934", "CVE-2024-27013", "CVE-2024-27020", "CVE-2024-35978", "CVE-2024-35982", "CVE-2024-35984", "CVE-2024-35997", "CVE-2024-36016", "CVE-2024-36902");
  script_tag(name:"creation_date", value:"2024-08-02 04:08:24 +0000 (Fri, 02 Aug 2024)");
  script_version("2024-09-09T05:05:49+0000");
  script_tag(name:"last_modification", value:"2024-09-09 05:05:49 +0000 (Mon, 09 Sep 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-06 13:11:05 +0000 (Fri, 06 Sep 2024)");

  script_name("Ubuntu: Security Advisory (USN-6926-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6926-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6926-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure, linux-azure-4.15' package(s) announced via the USN-6926-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Huang Si Cong discovered that the NFC Controller Interface (NCI) implementation in
the Linux kernel did not properly handle certain memory allocation failure
conditions, leading to a null pointer dereference vulnerability. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2023-46343)

It was discovered that a race condition existed in the Bluetooth subsystem
in the Linux kernel when modifying certain settings values through debugfs.
A privileged local attacker could use this to cause a denial of service.
(CVE-2024-24857, CVE-2024-24858, CVE-2024-24859)

Chenyuan Yang discovered that the Unsorted Block Images (UBI) flash device
volume management subsystem did not properly validate logical eraseblock
sizes in certain situations. An attacker could possibly use this to cause a
denial of service (system crash). (CVE-2024-25739)

Supraja Sridhara, Benedict Schluter, Mark Kuhne, Andrin Bertschi, and
Shweta Shinde discovered that the Confidential Computing framework in the
Linux kernel for x86 platforms did not properly handle 32-bit emulation on
TDX and SEV. An attacker with access to the VMM could use this to cause a
denial of service (guest crash) or possibly execute arbitrary code.
(CVE-2024-25744)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - GPU drivers,
 - HID subsystem,
 - I2C subsystem,
 - MTD block device drivers,
 - Network drivers,
 - TTY drivers,
 - USB subsystem,
 - File systems infrastructure,
 - F2FS file system,
 - SMB network file system,
 - BPF subsystem,
 - B.A.T.M.A.N. meshing protocol,
 - Bluetooth subsystem,
 - Networking core,
 - IPv4 networking,
 - IPv6 networking,
 - Netfilter,
 - Unix domain sockets,
 - AppArmor security module,
(CVE-2024-26884, CVE-2024-26882, CVE-2024-26923, CVE-2024-26840,
CVE-2023-52435, CVE-2024-35984, CVE-2024-26886, CVE-2023-52752,
CVE-2023-52436, CVE-2024-36016, CVE-2024-26857, CVE-2024-36902,
CVE-2023-52443, CVE-2024-35997, CVE-2024-35982, CVE-2023-52469,
CVE-2024-27020, CVE-2024-35978, CVE-2024-26934, CVE-2024-27013,
CVE-2023-52449, CVE-2024-26901, CVE-2023-52444, CVE-2023-52620)");

  script_tag(name:"affected", value:"'linux-azure, linux-azure-4.15' package(s) on Ubuntu 14.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1179-azure", ver:"4.15.0-1179.194~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"4.15.0.1179.194~14.04.1", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1179-azure", ver:"4.15.0-1179.194", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-lts-18.04", ver:"4.15.0.1179.147", rls:"UBUNTU18.04 LTS"))) {
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
