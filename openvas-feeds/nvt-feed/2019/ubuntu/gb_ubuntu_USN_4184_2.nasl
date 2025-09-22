# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844235");
  script_cve_id("CVE-2019-0155");
  script_tag(name:"creation_date", value:"2019-11-14 03:01:29 +0000 (Thu, 14 Nov 2019)");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-21 18:08:23 +0000 (Thu, 21 Nov 2019)");

  script_name("Ubuntu: Security Advisory (USN-4184-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|19\.04)");

  script_xref(name:"Advisory-ID", value:"USN-4184-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4184-2");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/bugs/1851709");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/bugs/1852141");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-hwe, linux-oem-osp1' package(s) announced via the USN-4184-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4184-1 fixed vulnerabilities in the Linux kernel. It was discovered
that the kernel fix for CVE-2019-0155 (i915 missing Blitter Command
Streamer check) was incomplete on 64-bit Intel x86 systems. Also, the
update introduced a regression that broke KVM guests where extended
page tables (EPT) are disabled or not supported. This update addresses
both issues.

We apologize for the inconvenience.

Original advisory details:

 Stephan van Schaik, Alyssa Milburn, Sebastian Osterlund, Pietro Frigo,
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

 Hui Peng discovered that the Atheros AR6004 USB Wi-Fi device driver for the
 Linux kernel did not properly validate endpoint descriptors returned by the
 device. A physically proximate attacker could use this to cause a denial of
 service (system crash). (CVE-2019-15098)

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

 Ori Nimron ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-hwe, linux-oem-osp1' package(s) on Ubuntu 18.04, Ubuntu 19.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-1028-oem-osp1", ver:"5.0.0-1028.32", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-36-generic", ver:"5.0.0-36.39~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-36-generic-lpae", ver:"5.0.0-36.39~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-36-lowlatency", ver:"5.0.0-36.39~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-18.04", ver:"5.0.0.36.94", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-18.04", ver:"5.0.0.36.94", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-18.04", ver:"5.0.0.36.94", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-osp1", ver:"5.0.0.1028.32", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-18.04", ver:"5.0.0.36.94", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU19.04") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-36-generic", ver:"5.0.0-36.39", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-36-generic-lpae", ver:"5.0.0-36.39", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-36-lowlatency", ver:"5.0.0-36.39", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"5.0.0.36.38", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"5.0.0.36.38", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"5.0.0.36.38", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"5.0.0.36.38", rls:"UBUNTU19.04"))) {
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
