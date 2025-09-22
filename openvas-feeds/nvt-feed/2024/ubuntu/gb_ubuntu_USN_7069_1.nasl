# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7069.1");
  script_cve_id("CVE-2023-52510", "CVE-2023-52528", "CVE-2024-26602", "CVE-2024-26641", "CVE-2024-26754", "CVE-2024-26810", "CVE-2024-26812", "CVE-2024-26960", "CVE-2024-27051", "CVE-2024-27436", "CVE-2024-31076", "CVE-2024-36971", "CVE-2024-38602", "CVE-2024-38611", "CVE-2024-38621", "CVE-2024-38627", "CVE-2024-38630", "CVE-2024-39487", "CVE-2024-39494", "CVE-2024-40901", "CVE-2024-40941", "CVE-2024-41073", "CVE-2024-41097", "CVE-2024-42089", "CVE-2024-42157", "CVE-2024-42223", "CVE-2024-42229", "CVE-2024-42244", "CVE-2024-42271", "CVE-2024-42280", "CVE-2024-42284", "CVE-2024-43858", "CVE-2024-44940", "CVE-2024-45016", "CVE-2024-46673");
  script_tag(name:"creation_date", value:"2024-10-17 04:07:56 +0000 (Thu, 17 Oct 2024)");
  script_version("2024-10-17T08:02:35+0000");
  script_tag(name:"last_modification", value:"2024-10-17 08:02:35 +0000 (Thu, 17 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-13 16:51:39 +0000 (Fri, 13 Sep 2024)");

  script_name("Ubuntu: Security Advisory (USN-7069-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7069-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7069-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-hwe, linux-azure-4.15, linux-gcp, linux-gcp-4.15, linux-hwe, linux-kvm, linux-oracle' package(s) announced via the USN-7069-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - x86 architecture,
 - Cryptographic API,
 - CPU frequency scaling framework,
 - HW tracing,
 - ISDN/mISDN subsystem,
 - Media drivers,
 - Network drivers,
 - NVME drivers,
 - S/390 drivers,
 - SCSI drivers,
 - USB subsystem,
 - VFIO drivers,
 - Watchdog drivers,
 - JFS file system,
 - IRQ subsystem,
 - Core kernel,
 - Memory management,
 - Amateur Radio drivers,
 - IPv4 networking,
 - IPv6 networking,
 - IUCV driver,
 - Network traffic control,
 - TIPC protocol,
 - XFRM subsystem,
 - Integrity Measurement Architecture(IMA) framework,
 - SoC Audio for Freescale CPUs drivers,
 - USB sound devices,
(CVE-2024-36971, CVE-2024-42271, CVE-2024-38630, CVE-2024-38602,
CVE-2024-42223, CVE-2024-44940, CVE-2023-52528, CVE-2024-41097,
CVE-2024-27051, CVE-2024-42157, CVE-2024-46673, CVE-2024-39494,
CVE-2024-42089, CVE-2024-41073, CVE-2024-26810, CVE-2024-26960,
CVE-2024-38611, CVE-2024-31076, CVE-2024-26754, CVE-2023-52510,
CVE-2024-40941, CVE-2024-45016, CVE-2024-38627, CVE-2024-38621,
CVE-2024-39487, CVE-2024-27436, CVE-2024-40901, CVE-2024-26812,
CVE-2024-42244, CVE-2024-42229, CVE-2024-43858, CVE-2024-42280,
CVE-2024-26641, CVE-2024-42284, CVE-2024-26602)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-hwe, linux-azure-4.15, linux-gcp, linux-gcp-4.15, linux-hwe, linux-kvm, linux-oracle' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1136-oracle", ver:"4.15.0-1136.147~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1167-gcp", ver:"4.15.0-1167.184~16.04.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1174-aws", ver:"4.15.0-1174.187~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-230-generic", ver:"4.15.0-230.242~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-230-lowlatency", ver:"4.15.0-230.242~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-hwe", ver:"4.15.0.1174.187~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"4.15.0.1167.184~16.04.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-16.04", ver:"4.15.0.230.242~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"4.15.0.1167.184~16.04.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-16.04", ver:"4.15.0.230.242~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem", ver:"4.15.0.230.242~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"4.15.0.1136.147~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-16.04", ver:"4.15.0.230.242~16.04.1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1136-oracle", ver:"4.15.0-1136.147", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1157-kvm", ver:"4.15.0-1157.162", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1167-gcp", ver:"4.15.0-1167.184", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1174-aws", ver:"4.15.0-1174.187", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1182-azure", ver:"4.15.0-1182.197", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-230-generic", ver:"4.15.0-230.242", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-230-lowlatency", ver:"4.15.0-230.242", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-lts-18.04", ver:"4.15.0.1174.172", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-lts-18.04", ver:"4.15.0.1182.150", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-lts-18.04", ver:"4.15.0.1167.180", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.15.0.230.214", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"4.15.0.1157.148", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.15.0.230.214", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-lts-18.04", ver:"4.15.0.1136.141", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"4.15.0.230.214", rls:"UBUNTU18.04 LTS"))) {
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
