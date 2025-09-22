# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7159.1");
  script_cve_id("CVE-2021-47076", "CVE-2021-47501", "CVE-2022-48733", "CVE-2022-48938", "CVE-2022-48943", "CVE-2023-52488", "CVE-2023-52497", "CVE-2023-52498", "CVE-2023-52639", "CVE-2024-26947", "CVE-2024-35904", "CVE-2024-35951", "CVE-2024-36938", "CVE-2024-36953", "CVE-2024-36968", "CVE-2024-38538", "CVE-2024-42068", "CVE-2024-42077", "CVE-2024-42156", "CVE-2024-42240", "CVE-2024-44940", "CVE-2024-44942", "CVE-2024-46724");
  script_tag(name:"creation_date", value:"2024-12-13 04:08:23 +0000 (Fri, 13 Dec 2024)");
  script_version("2024-12-13T15:40:54+0000");
  script_tag(name:"last_modification", value:"2024-12-13 15:40:54 +0000 (Fri, 13 Dec 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-27 16:09:10 +0000 (Tue, 27 Aug 2024)");

  script_name("Ubuntu: Security Advisory (USN-7159-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7159-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7159-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-gcp, linux-gcp-5.4, linux-hwe-5.4, linux-ibm, linux-ibm-5.4, linux-kvm, linux-raspi, linux-xilinx-zynqmp' package(s) announced via the USN-7159-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - ARM32 architecture,
 - ARM64 architecture,
 - S390 architecture,
 - x86 architecture,
 - Power management core,
 - GPU drivers,
 - InfiniBand drivers,
 - Network drivers,
 - S/390 drivers,
 - TTY drivers,
 - BTRFS file system,
 - EROFS file system,
 - F2FS file system,
 - File systems infrastructure,
 - BPF subsystem,
 - Socket messages infrastructure,
 - Bluetooth subsystem,
 - Ethernet bridge,
 - Networking core,
 - IPv4 networking,
 - SELinux security module,
(CVE-2022-48938, CVE-2024-42156, CVE-2024-36953, CVE-2024-38538,
CVE-2021-47501, CVE-2024-42068, CVE-2024-26947, CVE-2024-46724,
CVE-2024-36968, CVE-2023-52497, CVE-2024-35951, CVE-2023-52488,
CVE-2024-44940, CVE-2022-48733, CVE-2023-52498, CVE-2022-48943,
CVE-2024-35904, CVE-2024-42077, CVE-2024-36938, CVE-2023-52639,
CVE-2024-42240, CVE-2024-44942, CVE-2021-47076)");

  script_tag(name:"affected", value:"'linux, linux-gcp, linux-gcp-5.4, linux-hwe-5.4, linux-ibm, linux-ibm-5.4, linux-kvm, linux-raspi, linux-xilinx-zynqmp' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1083-ibm", ver:"5.4.0-1083.88~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1140-gcp", ver:"5.4.0-1140.149~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-202-generic", ver:"5.4.0-202.222~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-202-lowlatency", ver:"5.4.0-202.222~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"5.4.0.1140.149~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-18.04", ver:"5.4.0.202.222~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-ibm", ver:"5.4.0.1083.88~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-18.04", ver:"5.4.0.202.222~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem", ver:"5.4.0.202.222~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-osp1", ver:"5.4.0.202.222~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-snapdragon-hwe-18.04", ver:"5.4.0.202.222~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-18.04", ver:"5.4.0.202.222~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1055-xilinx-zynqmp", ver:"5.4.0-1055.59", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1083-ibm", ver:"5.4.0-1083.88", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1120-raspi", ver:"5.4.0-1120.132", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1124-kvm", ver:"5.4.0-1124.132", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1140-gcp", ver:"5.4.0-1140.149", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-202-generic", ver:"5.4.0-202.222", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-202-generic-lpae", ver:"5.4.0-202.222", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-202-lowlatency", ver:"5.4.0-202.222", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-lts-20.04", ver:"5.4.0.1140.142", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"5.4.0.202.198", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"5.4.0.202.198", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-ibm-lts-20.04", ver:"5.4.0.1083.112", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"5.4.0.1124.120", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"5.4.0.202.198", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem", ver:"5.4.0.202.198", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-osp1", ver:"5.4.0.202.198", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"5.4.0.1120.150", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi2", ver:"5.4.0.1120.150", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"5.4.0.202.198", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-xilinx-zynqmp", ver:"5.4.0.1055.55", rls:"UBUNTU20.04 LTS"))) {
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
