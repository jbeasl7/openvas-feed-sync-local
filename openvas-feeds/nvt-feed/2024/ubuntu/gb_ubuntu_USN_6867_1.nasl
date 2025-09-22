# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6867.1");
  script_cve_id("CVE-2021-47063", "CVE-2021-47070", "CVE-2023-52504", "CVE-2024-0841", "CVE-2024-26688", "CVE-2024-26712", "CVE-2024-26733", "CVE-2024-26735", "CVE-2024-26736", "CVE-2024-26748", "CVE-2024-26749", "CVE-2024-26751", "CVE-2024-26752", "CVE-2024-26754", "CVE-2024-26763", "CVE-2024-26764", "CVE-2024-26766", "CVE-2024-26772", "CVE-2024-26773", "CVE-2024-26777", "CVE-2024-26778", "CVE-2024-26779", "CVE-2024-26788", "CVE-2024-26790", "CVE-2024-26791", "CVE-2024-26793", "CVE-2024-26801", "CVE-2024-26804", "CVE-2024-26805", "CVE-2024-26835", "CVE-2024-26839", "CVE-2024-26840", "CVE-2024-26845", "CVE-2024-26848", "CVE-2024-27405", "CVE-2024-27410", "CVE-2024-27412", "CVE-2024-27413", "CVE-2024-27414", "CVE-2024-27416", "CVE-2024-27417");
  script_tag(name:"creation_date", value:"2024-07-04 04:08:00 +0000 (Thu, 04 Jul 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-20 15:56:00 +0000 (Fri, 20 Dec 2024)");

  script_name("Ubuntu: Security Advisory (USN-6867-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6867-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6867-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-bluefield, linux-iot' package(s) announced via the USN-6867-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the HugeTLB file system component of the Linux
Kernel contained a NULL pointer dereference vulnerability. A privileged
attacker could possibly use this to to cause a denial of service.
(CVE-2024-0841)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - ARM32 architecture,
 - PowerPC architecture,
 - x86 architecture,
 - DMA engine subsystem,
 - EFI core,
 - GPU drivers,
 - InfiniBand drivers,
 - Multiple devices driver,
 - Network drivers,
 - Power supply drivers,
 - TCM subsystem,
 - Userspace I/O drivers,
 - USB subsystem,
 - Framebuffer layer,
 - AFS file system,
 - File systems infrastructure,
 - BTRFS file system,
 - Ext4 file system,
 - Bluetooth subsystem,
 - Networking core,
 - IPv4 networking,
 - IPv6 networking,
 - L2TP protocol,
 - MAC80211 subsystem,
 - Netfilter,
 - Netlink,
 - Wireless networking,
(CVE-2021-47063, CVE-2024-26751, CVE-2024-26848, CVE-2024-26748,
CVE-2024-26733, CVE-2024-26735, CVE-2024-26805, CVE-2024-26804,
CVE-2024-26793, CVE-2023-52504, CVE-2024-27417, CVE-2024-27405,
CVE-2024-26778, CVE-2024-27414, CVE-2024-26801, CVE-2024-26835,
CVE-2024-27413, CVE-2024-26766, CVE-2024-27410, CVE-2024-27412,
CVE-2024-26773, CVE-2024-26777, CVE-2024-26839, CVE-2024-26764,
CVE-2024-26712, CVE-2024-26788, CVE-2024-26688, CVE-2024-26754,
CVE-2021-47070, CVE-2024-26752, CVE-2024-26845, CVE-2024-26791,
CVE-2024-26763, CVE-2024-27416, CVE-2024-26779, CVE-2024-26749,
CVE-2024-26736, CVE-2024-26840, CVE-2024-26772, CVE-2024-26790)");

  script_tag(name:"affected", value:"'linux-bluefield, linux-iot' package(s) on Ubuntu 20.04.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1038-iot", ver:"5.4.0-1038.39", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1086-bluefield", ver:"5.4.0-1086.93", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-bluefield", ver:"5.4.0.1086.82", rls:"UBUNTU20.04 LTS"))) {
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
