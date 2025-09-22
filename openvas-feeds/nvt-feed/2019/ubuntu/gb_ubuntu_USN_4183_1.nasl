# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844274");
  script_cve_id("CVE-2018-12207", "CVE-2019-0154", "CVE-2019-0155", "CVE-2019-11135", "CVE-2019-15791", "CVE-2019-15792", "CVE-2019-15793", "CVE-2019-16746", "CVE-2019-17666");
  script_tag(name:"creation_date", value:"2019-12-12 03:00:56 +0000 (Thu, 12 Dec 2019)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-21 18:30:04 +0000 (Mon, 21 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-4183-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU19\.10");

  script_xref(name:"Advisory-ID", value:"USN-4183-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4183-1");
  script_xref(name:"URL", value:"https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/TAA_MCEPSC_i915");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-azure, linux-gcp, linux-kvm, linux-oracle, linux-raspi2' package(s) announced via the USN-4183-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stephan van Schaik, Alyssa Milburn, Sebastian Osterlund, Pietro Frigo,
Kaveh Razavi, Herbert Bos, Cristiano Giuffrida, Giorgi Maisuradze, Moritz
Lipp, Michael Schwarz, Daniel Gruss, and Jo Van Bulck discovered that Intel
processors using Transactional Synchronization Extensions (TSX) could
expose memory contents previously stored in microarchitectural buffers to a
malicious process that is executing on the same CPU core. A local attacker
could use this to expose sensitive information. (CVE-2019-11135)

It was discovered that the Intel i915 graphics chipsets allowed userspace
to modify page table entries via writes to MMIO from the Blitter Command
Streamer and expose kernel memory information. A local attacker could use
this to expose sensitive information or possibly elevate privileges.
(CVE-2019-0155)

Deepak Gupta discovered that on certain Intel processors, the Linux kernel
did not properly perform invalidation on page table updates by virtual
guest operating systems. A local attacker in a guest VM could use this to
cause a denial of service (host system crash). (CVE-2018-12207)

It was discovered that the Intel i915 graphics chipsets could cause a
system hang when userspace performed a read from GT memory mapped input
output (MMIO) when the product is in certain low power states. A local
attacker could use this to cause a denial of service. (CVE-2019-0154)

Jann Horn discovered a reference count underflow in the shiftfs
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2019-15791)

Jann Horn discovered a type confusion vulnerability in the shiftfs
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2019-15792)

Jann Horn discovered that the shiftfs implementation in the Linux kernel
did not use the correct file system uid/gid when the user namespace of a
lower file system is not in the init user namespace. A local attacker could
use this to possibly bypass DAC permissions or have some other unspecified
impact. (CVE-2019-15793)

It was discovered that a buffer overflow existed in the 802.11 Wi-Fi
configuration interface for the Linux kernel when handling beacon settings.
A local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2019-16746)

Nico Waisman discovered that a buffer overflow existed in the Realtek Wi-Fi
driver for the Linux kernel when handling Notice of Absence frames. A
physically proximate attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2019-17666)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-azure, linux-gcp, linux-kvm, linux-oracle, linux-raspi2' package(s) on Ubuntu 19.10.");

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

if(release == "UBUNTU19.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-1006-oracle", ver:"5.3.0-1006.7", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-1007-aws", ver:"5.3.0-1007.8", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-1007-azure", ver:"5.3.0-1007.8", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-1007-kvm", ver:"5.3.0-1007.8", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-1008-gcp", ver:"5.3.0-1008.9", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-1012-raspi2", ver:"5.3.0-1012.14", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-22-generic", ver:"5.3.0-22.24", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-22-generic-lpae", ver:"5.3.0-22.24", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-22-lowlatency", ver:"5.3.0-22.24", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.3.0-22-snapdragon", ver:"5.3.0-22.24", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"5.3.0.1007.9", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"5.3.0.1007.25", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"5.3.0.1008.9", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"5.3.0.22.26", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"5.3.0.22.26", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"5.3.0.1008.9", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"5.3.0.1007.9", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"5.3.0.22.26", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"5.3.0.1006.7", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi2", ver:"5.3.0.1012.9", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-snapdragon", ver:"5.3.0.22.26", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"5.3.0.22.26", rls:"UBUNTU19.10"))) {
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
