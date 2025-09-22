# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705096");
  script_cve_id("CVE-2020-29374", "CVE-2020-36322", "CVE-2021-20317", "CVE-2021-20321", "CVE-2021-20322", "CVE-2021-22600", "CVE-2021-28711", "CVE-2021-28712", "CVE-2021-28713", "CVE-2021-28714", "CVE-2021-28715", "CVE-2021-28950", "CVE-2021-3640", "CVE-2021-3744", "CVE-2021-3752", "CVE-2021-3760", "CVE-2021-3764", "CVE-2021-3772", "CVE-2021-38300", "CVE-2021-39685", "CVE-2021-39686", "CVE-2021-39698", "CVE-2021-39713", "CVE-2021-4002", "CVE-2021-4083", "CVE-2021-4135", "CVE-2021-4155", "CVE-2021-41864", "CVE-2021-4202", "CVE-2021-4203", "CVE-2021-42739", "CVE-2021-43389", "CVE-2021-43975", "CVE-2021-43976", "CVE-2021-44733", "CVE-2021-45095", "CVE-2021-45469", "CVE-2021-45480", "CVE-2022-0001", "CVE-2022-0002", "CVE-2022-0322", "CVE-2022-0330", "CVE-2022-0435", "CVE-2022-0487", "CVE-2022-0492", "CVE-2022-0617", "CVE-2022-22942", "CVE-2022-24448", "CVE-2022-24959", "CVE-2022-25258", "CVE-2022-25375");
  script_tag(name:"creation_date", value:"2022-03-10 02:01:05 +0000 (Thu, 10 Mar 2022)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-07 19:43:55 +0000 (Thu, 07 Apr 2022)");

  script_name("Debian: Security Advisory (DSA-5096-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-5096-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/DSA-5096-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5096");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-5096-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2020-29374

Jann Horn of Google reported a flaw in Linux's virtual memory management. A parent and child process initially share all their memory, but when either writes to a shared page, the page is duplicated and unshared (copy-on-write). However, in case an operation such as vmsplice() required the kernel to take an additional reference to a shared page, and a copy-on-write occurs during this operation, the kernel might have accessed the wrong process's memory. For some programs, this could lead to an information leak or data corruption.

This issue was already fixed for most architectures, but not on MIPS and System z. This update corrects that.

CVE-2020-36322, CVE-2021-28950 The syzbot tool found that the FUSE (filesystem-in-user-space) implementation did not correctly handle a FUSE server returning invalid attributes for a file. A local user permitted to run a FUSE server could use this to cause a denial of service (crash). The original fix for this introduced a different potential denial of service (infinite loop in kernel space), which has also been fixed.

CVE-2021-3640

Lin Ma discovered a race condition in the Bluetooth protocol implementation that can lead to a use-after-free. A local user could exploit this to cause a denial of service (memory corruption or crash) or possibly for privilege escalation.

CVE-2021-3744, CVE-2021-3764 minihanshen reported bugs in the ccp driver for AMD Cryptographic Coprocessors that could lead to a resource leak. On systems using this driver, a local user could exploit this to cause a denial of service.

CVE-2021-3752

Likang Luo of NSFOCUS Security Team discovered a flaw in the Bluetooth L2CAP implementation that can lead to a user-after-free. A local user could exploit this to cause a denial of service (memory corruption or crash) or possibly for privilege escalation.

CVE-2021-3760, CVE-2021-4202 Lin Ma discovered race conditions in the NCI (NFC Controller Interface) driver, which could lead to a use-after-free. A local user could exploit this to cause a denial of service (memory corruption or crash) or possibly for privilege escalation. This driver is not enabled in Debian's official kernel configurations.

CVE-2021-3772

A flaw was found in the SCTP protocol implementation, which would allow a networked attacker to break an SCTP association. The attacker would only need to know or guess the IP addresses and ports for the association.

CVE-2021-4002

It was discovered that hugetlbfs, the virtual filesystem used by applications to allocate huge pages in RAM, did not flush the CPU's TLB in one case where it was necessary. In some circumstances a local user would be able to read and write huge pages after they are freed and reallocated to a different process. This could lead to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-4.19.0-19-s390x-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-4.19.0-19-s390x-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"compress-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"compress-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"compress-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"compress-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"compress-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"compress-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"compress-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"compress-modules-4.19.0-19-s390x-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-4.19.0-19-s390x-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-4.19.0-19-s390x-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-4.19.0-19-s390x-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-extra-modules-4.19.0-19-s390x-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-modules-4.19.0-19-s390x-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-4.19.0-19-s390x-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fancontrol-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-4.19.0-19-s390x-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-4.19.0-19-s390x-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hfs-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-daemons", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hypervisor-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-4.19.0-19-s390x-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jffs2-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-4.19.0-19-s390x-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"leds-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"leds-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbpf-dev", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbpf4.19", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcpupower-dev", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcpupower1", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-8-arm", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-8-s390", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-8-x86", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-config-4.19", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-cpupower", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-4.19", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-4kc-malta", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-5kc-malta", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-686", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-686-pae", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-all", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-all-amd64", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-all-arm64", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-all-armel", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-all-armhf", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-all-i386", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-all-mips", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-all-mips64el", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-all-mipsel", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-all-ppc64el", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-all-s390x", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-amd64", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-arm64", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-armmp", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-armmp-lpae", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-cloud-amd64", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-common", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-common-rt", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-loongson-3", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-marvell", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-octeon", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-powerpc64le", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-rpi", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-rt-686-pae", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-rt-amd64", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-rt-arm64", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-rt-armmp", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-s390x", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-4kc-malta", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-4kc-malta-dbg", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-5kc-malta", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-5kc-malta-dbg", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-686-dbg", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-686-pae-dbg", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-686-pae-unsigned", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-686-unsigned", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-amd64-dbg", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-amd64-unsigned", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-arm64-dbg", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-arm64-unsigned", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-armmp", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-armmp-dbg", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-armmp-lpae", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-armmp-lpae-dbg", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-cloud-amd64-dbg", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-cloud-amd64-unsigned", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-loongson-3", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-loongson-3-dbg", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-marvell", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-marvell-dbg", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-octeon", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-octeon-dbg", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-powerpc64le", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-powerpc64le-dbg", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-rpi", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-rpi-dbg", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-rt-686-pae-dbg", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-rt-686-pae-unsigned", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-rt-amd64-dbg", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-rt-amd64-unsigned", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-rt-arm64-dbg", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-rt-arm64-unsigned", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-rt-armmp", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-rt-armmp-dbg", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-s390x", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-s390x-dbg", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-signed-template", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-arm64-signed-template", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-i386-signed-template", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-4.19", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-perf-4.19", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-4.19", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.19.0-19", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-4.19.0-19-s390x-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-4.19.0-19-s390x-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-4.19.0-19-s390x-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-4.19.0-19-s390x-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-4.19.0-19-s390x-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-4.19.0-19-s390x-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rtc-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-4.19.0-19-s390x-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-4.19.0-19-s390x-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-4.19.0-19-s390x-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usbip", ver:"2.0+4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.19.0-19-powerpc64le-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-4.19.0-19-s390x-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.19.0-19-4kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.19.0-19-5kc-malta-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.19.0-19-armmp-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.19.0-19-loongson-3-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.19.0-19-marvell-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.19.0-19-octeon-di", ver:"4.19.232-1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-4.19.0-19-s390x-di", ver:"4.19.232-1", rls:"DEB10"))) {
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
