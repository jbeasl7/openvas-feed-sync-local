# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7332.1");
  script_cve_id("CVE-2021-47103", "CVE-2021-47606", "CVE-2022-48994", "CVE-2023-52488", "CVE-2023-52522", "CVE-2023-52799", "CVE-2023-52818", "CVE-2023-52880", "CVE-2024-26685", "CVE-2024-35896", "CVE-2024-36886", "CVE-2024-36952", "CVE-2024-36964", "CVE-2024-38567", "CVE-2024-40910", "CVE-2024-40911", "CVE-2024-40943", "CVE-2024-40981", "CVE-2024-41063", "CVE-2024-41064", "CVE-2024-42068", "CVE-2024-42070", "CVE-2024-43854", "CVE-2024-43863", "CVE-2024-43892", "CVE-2024-43893", "CVE-2024-43900", "CVE-2024-44931", "CVE-2024-44938", "CVE-2024-49902", "CVE-2024-50117", "CVE-2024-50148", "CVE-2024-50171", "CVE-2024-50233", "CVE-2024-53104", "CVE-2024-53156");
  script_tag(name:"creation_date", value:"2025-03-06 04:04:12 +0000 (Thu, 06 Mar 2025)");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-07 16:02:00 +0000 (Tue, 07 Jan 2025)");

  script_name("Ubuntu: Security Advisory (USN-7332-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7332-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7332-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws' package(s) announced via the USN-7332-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - PowerPC architecture,
 - Block layer subsystem,
 - GPIO subsystem,
 - GPU drivers,
 - Media drivers,
 - Network drivers,
 - SCSI subsystem,
 - Direct Digital Synthesis drivers,
 - TTY drivers,
 - 9P distributed file system,
 - JFS file system,
 - NILFS2 file system,
 - File systems infrastructure,
 - BPF subsystem,
 - Netfilter,
 - Network sockets,
 - Memory management,
 - Amateur Radio drivers,
 - B.A.T.M.A.N. meshing protocol,
 - Bluetooth subsystem,
 - Ethernet bridge,
 - Networking core,
 - IPv4 networking,
 - IPv6 networking,
 - Netlink,
 - TIPC protocol,
 - Wireless networking,
 - ALSA framework,
(CVE-2022-48994, CVE-2024-43900, CVE-2024-40943, CVE-2024-41063,
CVE-2024-42070, CVE-2024-38567, CVE-2024-36964, CVE-2023-52522,
CVE-2024-53156, CVE-2024-53104, CVE-2024-43854, CVE-2024-42068,
CVE-2023-52818, CVE-2024-44931, CVE-2021-47103, CVE-2023-52799,
CVE-2024-43893, CVE-2024-36886, CVE-2024-49902, CVE-2024-36952,
CVE-2024-40911, CVE-2023-52488, CVE-2024-35896, CVE-2024-50117,
CVE-2024-50171, CVE-2021-47606, CVE-2024-40910, CVE-2024-43892,
CVE-2024-50148, CVE-2024-41064, CVE-2024-44938, CVE-2024-50233,
CVE-2023-52880, CVE-2024-43863, CVE-2024-26685, CVE-2024-40981)");

  script_tag(name:"affected", value:"'linux, linux-aws' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1141-aws", ver:"4.4.0-1141.147", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1141.138", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1179-aws", ver:"4.4.0-1179.194", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-266-generic", ver:"4.4.0-266.300", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-266-lowlatency", ver:"4.4.0-266.300", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1179.183", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.4.0.266.272", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lts-xenial", ver:"4.4.0.266.272", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.4.0.266.272", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-lts-xenial", ver:"4.4.0.266.272", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"4.4.0.266.272", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-lts-xenial", ver:"4.4.0.266.272", rls:"UBUNTU16.04 LTS"))) {
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
