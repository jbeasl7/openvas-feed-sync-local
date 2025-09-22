# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7121.1");
  script_cve_id("CVE-2022-48733", "CVE-2022-48938", "CVE-2022-48943", "CVE-2023-52502", "CVE-2023-52531", "CVE-2023-52578", "CVE-2023-52599", "CVE-2023-52612", "CVE-2023-52614", "CVE-2023-52639", "CVE-2024-26633", "CVE-2024-26636", "CVE-2024-26668", "CVE-2024-26675", "CVE-2024-27397", "CVE-2024-35877", "CVE-2024-36020", "CVE-2024-36953", "CVE-2024-38538", "CVE-2024-38560", "CVE-2024-38596", "CVE-2024-38637", "CVE-2024-41059", "CVE-2024-41071", "CVE-2024-41089", "CVE-2024-41095", "CVE-2024-42094", "CVE-2024-42104", "CVE-2024-42240", "CVE-2024-42309", "CVE-2024-42310", "CVE-2024-43854", "CVE-2024-43882", "CVE-2024-44942", "CVE-2024-44987", "CVE-2024-44998", "CVE-2024-46722", "CVE-2024-46723", "CVE-2024-46738", "CVE-2024-46743", "CVE-2024-46756", "CVE-2024-46757", "CVE-2024-46758", "CVE-2024-46759", "CVE-2024-46800");
  script_tag(name:"creation_date", value:"2024-11-20 15:33:16 +0000 (Wed, 20 Nov 2024)");
  script_version("2024-11-21T05:05:26+0000");
  script_tag(name:"last_modification", value:"2024-11-21 05:05:26 +0000 (Thu, 21 Nov 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-20 17:18:55 +0000 (Fri, 20 Sep 2024)");

  script_name("Ubuntu: Security Advisory (USN-7121-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7121-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7121-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-hwe, linux-azure, linux-azure-4.15, linux-gcp, linux-gcp-4.15, linux-hwe, linux-kvm, linux-oracle' package(s) announced via the USN-7121-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - ARM64 architecture,
 - S390 architecture,
 - x86 architecture,
 - Block layer subsystem,
 - Cryptographic API,
 - ATM drivers,
 - Device frequency scaling framework,
 - GPU drivers,
 - Hardware monitoring drivers,
 - VMware VMCI Driver,
 - Network drivers,
 - Device tree and open firmware driver,
 - SCSI drivers,
 - Greybus lights staging drivers,
 - BTRFS file system,
 - File systems infrastructure,
 - F2FS file system,
 - JFS file system,
 - NILFS2 file system,
 - Netfilter,
 - Memory management,
 - Ethernet bridge,
 - IPv6 networking,
 - IUCV driver,
 - Logical Link layer,
 - MAC80211 subsystem,
 - NFC subsystem,
 - Network traffic control,
 - Unix domain sockets,
(CVE-2023-52614, CVE-2024-26633, CVE-2024-46758, CVE-2024-46723,
CVE-2023-52502, CVE-2024-41059, CVE-2024-44987, CVE-2024-36020,
CVE-2023-52599, CVE-2023-52639, CVE-2024-26668, CVE-2024-42094,
CVE-2022-48938, CVE-2022-48733, CVE-2024-27397, CVE-2023-52578,
CVE-2024-38560, CVE-2024-38538, CVE-2024-42310, CVE-2024-46722,
CVE-2024-46800, CVE-2024-41095, CVE-2024-42104, CVE-2024-35877,
CVE-2022-48943, CVE-2024-46743, CVE-2023-52531, CVE-2024-46757,
CVE-2024-36953, CVE-2024-46756, CVE-2024-38596, CVE-2023-52612,
CVE-2024-38637, CVE-2024-41071, CVE-2024-46759, CVE-2024-43882,
CVE-2024-26675, CVE-2024-43854, CVE-2024-44942, CVE-2024-44998,
CVE-2024-42240, CVE-2024-41089, CVE-2024-26636, CVE-2024-46738,
CVE-2024-42309)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-hwe, linux-azure, linux-azure-4.15, linux-gcp, linux-gcp-4.15, linux-hwe, linux-kvm, linux-oracle' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1168-gcp", ver:"4.15.0-1168.185~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1175-aws", ver:"4.15.0-1175.188~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1183-azure", ver:"4.15.0-1183.198~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-231-generic", ver:"4.15.0-231.243~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-231-lowlatency", ver:"4.15.0-231.243~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-hwe", ver:"4.15.0.1175.188~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"4.15.0.1183.198~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"4.15.0.1168.185~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-16.04", ver:"4.15.0.231.243~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"4.15.0.1168.185~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-16.04", ver:"4.15.0.231.243~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem", ver:"4.15.0.231.243~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-16.04", ver:"4.15.0.231.243~16.04.1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1137-oracle", ver:"4.15.0-1137.148", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1158-kvm", ver:"4.15.0-1158.163", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1168-gcp", ver:"4.15.0-1168.185", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1175-aws", ver:"4.15.0-1175.188", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1183-azure", ver:"4.15.0-1183.198", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-231-generic", ver:"4.15.0-231.243", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-231-lowlatency", ver:"4.15.0-231.243", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-lts-18.04", ver:"4.15.0.1175.173", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-lts-18.04", ver:"4.15.0.1183.151", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-lts-18.04", ver:"4.15.0.1168.181", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.15.0.231.215", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"4.15.0.1158.149", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.15.0.231.215", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-lts-18.04", ver:"4.15.0.1137.142", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"4.15.0.231.215", rls:"UBUNTU18.04 LTS"))) {
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
