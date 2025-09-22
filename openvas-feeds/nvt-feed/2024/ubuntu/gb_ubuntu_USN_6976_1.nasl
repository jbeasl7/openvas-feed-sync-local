# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6976.1");
  script_cve_id("CVE-2021-46904", "CVE-2021-46906", "CVE-2021-46924", "CVE-2021-47171", "CVE-2021-47173", "CVE-2021-47518", "CVE-2021-47521", "CVE-2021-47542", "CVE-2021-47571", "CVE-2022-48659", "CVE-2023-52470", "CVE-2023-52629", "CVE-2023-52644", "CVE-2023-52760", "CVE-2023-52806", "CVE-2024-22099", "CVE-2024-24860", "CVE-2024-26600", "CVE-2024-26654", "CVE-2024-26679", "CVE-2024-26687", "CVE-2024-26903", "CVE-2024-26929", "CVE-2024-27013", "CVE-2024-36901", "CVE-2024-39292", "CVE-2024-39484");
  script_tag(name:"creation_date", value:"2024-08-23 04:09:10 +0000 (Fri, 23 Aug 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-24 01:12:54 +0000 (Fri, 24 May 2024)");

  script_name("Ubuntu: Security Advisory (USN-6976-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6976-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6976-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-kvm, linux-lts-xenial' package(s) announced via the USN-6976-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Yuxuan Hu discovered that the Bluetooth RFCOMM protocol driver in the Linux
Kernel contained a race condition, leading to a NULL pointer dereference.
An attacker could possibly use this to cause a denial of service (system
crash). (CVE-2024-22099)

It was discovered that a race condition existed in the Bluetooth subsystem
in the Linux kernel, leading to a null pointer dereference vulnerability. A
privileged local attacker could use this to possibly cause a denial of
service (system crash). (CVE-2024-24860)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - SuperH RISC architecture,
 - User-Mode Linux (UML),
 - GPU drivers,
 - HID subsystem,
 - MMC subsystem,
 - Network drivers,
 - PHY drivers,
 - SCSI drivers,
 - USB subsystem,
 - Xen hypervisor drivers,
 - GFS2 file system,
 - Memory management,
 - Bluetooth subsystem,
 - IPv4 networking,
 - IPv6 networking,
 - NFC subsystem,
 - HD-audio driver,
 - ALSA SH drivers,
(CVE-2023-52806, CVE-2021-46924, CVE-2021-47521, CVE-2021-47542,
CVE-2024-26903, CVE-2024-26654, CVE-2024-27013, CVE-2024-26600,
CVE-2021-47518, CVE-2021-47171, CVE-2023-52629, CVE-2023-52644,
CVE-2021-46904, CVE-2023-52470, CVE-2024-36901, CVE-2021-46906,
CVE-2024-39292, CVE-2022-48659, CVE-2021-47173, CVE-2021-47571,
CVE-2024-26929, CVE-2024-39484, CVE-2024-26687, CVE-2024-26679,
CVE-2023-52760)");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1135-aws", ver:"4.4.0-1135.141", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-258-generic", ver:"4.4.0-258.292~14.04.2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-258-lowlatency", ver:"4.4.0-258.292~14.04.2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1135.132", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lts-xenial", ver:"4.4.0.258.292~14.04.2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-lts-xenial", ver:"4.4.0.258.292~14.04.2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-lts-xenial", ver:"4.4.0.258.292~14.04.2", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1136-kvm", ver:"4.4.0-1136.146", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1173-aws", ver:"4.4.0-1173.188", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-258-generic", ver:"4.4.0-258.292", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-258-lowlatency", ver:"4.4.0-258.292", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1173.177", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.4.0.258.264", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lts-xenial", ver:"4.4.0.258.264", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"4.4.0.1136.133", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.4.0.258.264", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-lts-xenial", ver:"4.4.0.258.264", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"4.4.0.258.264", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-lts-xenial", ver:"4.4.0.258.264", rls:"UBUNTU16.04 LTS"))) {
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
