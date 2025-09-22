# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6938.1");
  script_cve_id("CVE-2021-46932", "CVE-2021-46933", "CVE-2021-46960", "CVE-2021-47194", "CVE-2022-48619", "CVE-2023-46343", "CVE-2023-52436", "CVE-2023-52444", "CVE-2023-52449", "CVE-2023-52469", "CVE-2023-52620", "CVE-2023-52752", "CVE-2024-24857", "CVE-2024-24858", "CVE-2024-24859", "CVE-2024-25739", "CVE-2024-26840", "CVE-2024-26857", "CVE-2024-26882", "CVE-2024-26884", "CVE-2024-26886", "CVE-2024-26901", "CVE-2024-26923", "CVE-2024-26934", "CVE-2024-27020", "CVE-2024-35978", "CVE-2024-35982", "CVE-2024-35984", "CVE-2024-35997", "CVE-2024-36016", "CVE-2024-36902");
  script_tag(name:"creation_date", value:"2024-08-01 04:08:31 +0000 (Thu, 01 Aug 2024)");
  script_version("2024-08-01T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-08-01 05:05:42 +0000 (Thu, 01 Aug 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-23 19:13:43 +0000 (Thu, 23 May 2024)");

  script_name("Ubuntu: Security Advisory (USN-6938-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6938-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6938-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-kvm, linux-lts-xenial' package(s) announced via the USN-6938-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the device input subsystem in the Linux kernel did
not properly handle the case when an event code falls outside of a bitmap.
A local attacker could use this to cause a denial of service (system
crash). (CVE-2022-48619)

Huang Si Cong discovered that the NFC Controller Interface (NCI) implementation in
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

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - GPU drivers,
 - HID subsystem,
 - I2C subsystem,
 - Input Device Drivers (Mouse),
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
 - IPv4 networking,
 - IPv6 networking,
 - Netfilter,
 - Unix domain sockets,
 - Wireless networking,
(CVE-2024-26901, CVE-2021-46932, CVE-2024-26857, CVE-2024-26882,
CVE-2024-26934, CVE-2023-52449, CVE-2024-35982, CVE-2021-46933,
CVE-2023-52620, CVE-2023-52444, CVE-2024-26923, CVE-2023-52469,
CVE-2024-26886, CVE-2024-36902, CVE-2023-52436, CVE-2024-36016,
CVE-2024-26884, CVE-2021-46960, CVE-2021-47194, CVE-2023-52752,
CVE-2024-27020, CVE-2024-26840, CVE-2024-35997, CVE-2024-35984,
CVE-2024-35978)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-kvm, linux-lts-xenial' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1134-aws", ver:"4.4.0-1134.140", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-257-generic", ver:"4.4.0-257.291~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-257-lowlatency", ver:"4.4.0-257.291~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1134.131", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lts-xenial", ver:"4.4.0.257.291~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-lts-xenial", ver:"4.4.0.257.291~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-lts-xenial", ver:"4.4.0.257.291~14.04.1", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1135-kvm", ver:"4.4.0-1135.145", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1172-aws", ver:"4.4.0-1172.187", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-257-generic", ver:"4.4.0-257.291", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-257-lowlatency", ver:"4.4.0-257.291", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1172.176", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.4.0.257.263", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lts-xenial", ver:"4.4.0.257.263", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"4.4.0.1135.132", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.4.0.257.263", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-lts-xenial", ver:"4.4.0.257.263", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"4.4.0.257.263", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-lts-xenial", ver:"4.4.0.257.263", rls:"UBUNTU16.04 LTS"))) {
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
