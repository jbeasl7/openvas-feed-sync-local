# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8033.5");
  script_cve_id("CVE-2024-53114", "CVE-2024-56538", "CVE-2024-58011", "CVE-2025-21861", "CVE-2025-22058", "CVE-2025-23143", "CVE-2025-38236", "CVE-2025-38248", "CVE-2025-38584", "CVE-2025-39869", "CVE-2025-39873", "CVE-2025-39876", "CVE-2025-39880", "CVE-2025-39883", "CVE-2025-39885", "CVE-2025-39907", "CVE-2025-39911", "CVE-2025-39913", "CVE-2025-39923", "CVE-2025-39934", "CVE-2025-39937", "CVE-2025-39943", "CVE-2025-39945", "CVE-2025-39949", "CVE-2025-39951", "CVE-2025-39953", "CVE-2025-39955", "CVE-2025-39967", "CVE-2025-39968", "CVE-2025-39969", "CVE-2025-39970", "CVE-2025-39971", "CVE-2025-39972", "CVE-2025-39973", "CVE-2025-39980", "CVE-2025-39985", "CVE-2025-39986", "CVE-2025-39987", "CVE-2025-39988", "CVE-2025-39994", "CVE-2025-39995", "CVE-2025-39996", "CVE-2025-39998", "CVE-2025-40001", "CVE-2025-40006", "CVE-2025-40011", "CVE-2025-40020", "CVE-2025-40021", "CVE-2025-40026", "CVE-2025-40027", "CVE-2025-40029", "CVE-2025-40030", "CVE-2025-40035", "CVE-2025-40042", "CVE-2025-40043", "CVE-2025-40044", "CVE-2025-40048", "CVE-2025-40049", "CVE-2025-40053", "CVE-2025-40055", "CVE-2025-40060", "CVE-2025-40068", "CVE-2025-40070", "CVE-2025-40078", "CVE-2025-40081", "CVE-2025-40085", "CVE-2025-40087", "CVE-2025-40088", "CVE-2025-40092", "CVE-2025-40094", "CVE-2025-40105", "CVE-2025-40106", "CVE-2025-40109", "CVE-2025-40111", "CVE-2025-40112", "CVE-2025-40115", "CVE-2025-40116", "CVE-2025-40118", "CVE-2025-40120", "CVE-2025-40121", "CVE-2025-40124", "CVE-2025-40125", "CVE-2025-40126", "CVE-2025-40127", "CVE-2025-40134", "CVE-2025-40140", "CVE-2025-40153", "CVE-2025-40154", "CVE-2025-40167", "CVE-2025-40171", "CVE-2025-40173", "CVE-2025-40178", "CVE-2025-40179", "CVE-2025-40183", "CVE-2025-40187", "CVE-2025-40188", "CVE-2025-40194", "CVE-2025-40200", "CVE-2025-40204", "CVE-2025-40205", "CVE-2025-40215", "CVE-2025-40219", "CVE-2025-40220", "CVE-2025-40223", "CVE-2025-40231", "CVE-2025-40233", "CVE-2025-40240", "CVE-2025-40243", "CVE-2025-40244", "CVE-2025-40245", "CVE-2025-40346", "CVE-2025-40349", "CVE-2025-40351", "CVE-2025-68249");
  script_tag(name:"creation_date", value:"2026-02-19 04:37:45 +0000 (Thu, 19 Feb 2026)");
  script_version("2026-02-27T05:55:46+0000");
  script_tag(name:"last_modification", value:"2026-02-27 05:55:46 +0000 (Fri, 27 Feb 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-26 23:06:19 +0000 (Thu, 26 Feb 2026)");

  script_name("Ubuntu: Security Advisory (USN-8033-5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-8033-5");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8033-5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-gcp-5.15, linux-kvm, linux-oracle, linux-oracle-5.15' package(s) announced via the USN-8033-5 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - Nios II architecture,
 - Sun Sparc architecture,
 - User-Mode Linux (UML),
 - x86 architecture,
 - Block layer subsystem,
 - Cryptographic API,
 - Drivers core,
 - Bus devices,
 - Hardware random number generator core,
 - Data acquisition framework and drivers,
 - CPU frequency scaling framework,
 - DMA engine subsystem,
 - GPU drivers,
 - HW tracing,
 - Input Device (Miscellaneous) drivers,
 - Multiple devices driver,
 - Media drivers,
 - MOST (Media Oriented Systems Transport) drivers,
 - MTD block device drivers,
 - Network drivers,
 - NVME drivers,
 - PCI subsystem,
 - Performance monitor drivers,
 - Pin controllers subsystem,
 - x86 platform drivers,
 - PPS (Pulse Per Second) driver,
 - PWM drivers,
 - SCSI subsystem,
 - TCM subsystem,
 - Userspace I/O drivers,
 - USB Gadget drivers,
 - USB Host Controller drivers,
 - Framebuffer layer,
 - BTRFS file system,
 - File systems infrastructure,
 - Ext4 file system,
 - Network file system (NFS) server daemon,
 - NTFS3 file system,
 - SMB network file system,
 - padata parallel execution mechanism,
 - IP tunnels definitions,
 - Network sockets,
 - XFRM subsystem,
 - Control group (cgroup),
 - Padata parallel execution mechanism,
 - PID allocator,
 - Tracing infrastructure,
 - Memory management,
 - 9P file system network protocol,
 - Ethernet bridge,
 - Ceph Core library,
 - Networking core,
 - IPv4 networking,
 - IPv6 networking,
 - NFC subsystem,
 - RF switch subsystem,
 - SCTP protocol,
 - Unix domain sockets,
 - VMware vSockets driver,
 - Intel ASoC drivers,
 - USB sound devices,
(CVE-2024-53114, CVE-2024-56538, CVE-2024-58011, CVE-2025-21861,
CVE-2025-22058, CVE-2025-23143, CVE-2025-38236, CVE-2025-38248,
CVE-2025-38584, CVE-2025-39869, CVE-2025-39873, CVE-2025-39876,
CVE-2025-39880, CVE-2025-39883, CVE-2025-39885, CVE-2025-39907,
CVE-2025-39911, CVE-2025-39913, CVE-2025-39923, CVE-2025-39934,
CVE-2025-39937, CVE-2025-39943, CVE-2025-39945, CVE-2025-39949,
CVE-2025-39951, CVE-2025-39953, CVE-2025-39955, CVE-2025-39967,
CVE-2025-39968, CVE-2025-39969, CVE-2025-39970, CVE-2025-39971,
CVE-2025-39972, CVE-2025-39973, CVE-2025-39980, CVE-2025-39985,
CVE-2025-39986, CVE-2025-39987, CVE-2025-39988, CVE-2025-39994,
CVE-2025-39995, CVE-2025-39996, CVE-2025-39998, CVE-2025-40001,
CVE-2025-40006, CVE-2025-40011, CVE-2025-40020, CVE-2025-40021,
CVE-2025-40026, CVE-2025-40027, CVE-2025-40029, CVE-2025-40030,
CVE-2025-40035, CVE-2025-40042, CVE-2025-40043, CVE-2025-40044,
CVE-2025-40048, CVE-2025-40049, CVE-2025-40053, CVE-2025-40055,
CVE-2025-40060, CVE-2025-40068, CVE-2025-40070, CVE-2025-40078,
CVE-2025-40081, CVE-2025-40085, CVE-2025-40087, CVE-2025-40088,
CVE-2025-40092, CVE-2025-40094, CVE-2025-40105, CVE-2025-40106,
CVE-2025-40109, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-gcp-5.15, linux-kvm, linux-oracle, linux-oracle-5.15' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1097-oracle", ver:"5.15.0-1097.103~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1100-gcp", ver:"5.15.0-1100.109~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"5.15.0.1100.109~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-5.15", ver:"5.15.0.1100.109~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"5.15.0.1097.103~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-5.15", ver:"5.15.0.1097.103~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1092-kvm", ver:"5.15.0-1092.97", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1097-oracle", ver:"5.15.0-1097.103", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"5.15.0.1092.88", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm-5.15", ver:"5.15.0.1092.88", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-5.15", ver:"5.15.0.1097.93", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-lts-22.04", ver:"5.15.0.1097.93", rls:"UBUNTU22.04 LTS"))) {
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
