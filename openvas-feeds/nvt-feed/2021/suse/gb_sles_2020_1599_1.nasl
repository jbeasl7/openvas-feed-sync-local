# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1599.1");
  script_cve_id("CVE-2018-1000199", "CVE-2019-19462", "CVE-2019-20806", "CVE-2019-20812", "CVE-2019-9455", "CVE-2020-0543", "CVE-2020-10690", "CVE-2020-10711", "CVE-2020-10720", "CVE-2020-10732", "CVE-2020-10751", "CVE-2020-10757", "CVE-2020-12114", "CVE-2020-12464", "CVE-2020-12652", "CVE-2020-12653", "CVE-2020-12654", "CVE-2020-12655", "CVE-2020-12656", "CVE-2020-12657", "CVE-2020-12659", "CVE-2020-12768", "CVE-2020-12769", "CVE-2020-13143");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:01 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-07 20:57:04 +0000 (Thu, 07 May 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1599-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1599-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201599-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:1599-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP1 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2020-0543: Fixed a side channel attack against special registers
 which could have resulted in leaking of read values to cores other than
 the one which called it. This attack is known as Special Register Buffer
 Data Sampling (SRBDS) or 'CrossTalk' (bsc#1154824).

CVE-2020-13143: Fixed an out-of-bounds read in gadget_dev_desc_UDC_store
 in drivers/usb/gadget/configfs.c (bsc#1171982).

CVE-2020-12769: Fixed an issue which could have allowed attackers to
 cause a panic via concurrent calls to dw_spi_irq and dw_spi_transfer_one
 (bsc#1171983).

CVE-2020-12768: Fixed a memory leak in svm_cpu_uninit in
 arch/x86/kvm/svm.c (bsc#1171736).

CVE-2020-12659: Fixed an out-of-bounds write (by a user with the
 CAP_NET_ADMIN capability) due to improper headroom validation
 (bsc#1171214).

CVE-2020-12657: An a use-after-free in block/bfq-iosched.c (bsc#1171205).

CVE-2020-12656: Fixed an improper handling of certain domain_release
 calls leadingch could have led to a memory leak (bsc#1171219).

CVE-2020-12655: Fixed an issue which could have allowed attackers to
 trigger a sync of excessive duration via an XFS v5 image with crafted
 metadata (bsc#1171217).

CVE-2020-12654: Fixed an issue in he wifi driver which could have
 allowed a remote AP to trigger a heap-based buffer overflow
 (bsc#1171202).

CVE-2020-12653: Fixed an issue in the wifi driver which could have
 allowed local users to gain privileges or cause a denial of service
 (bsc#1171195).

CVE-2020-12652: Fixed an issue which could have allowed local users to
 hold an incorrect lock during the ioctl operation and trigger a race
 condition (bsc#1171218).

CVE-2020-12464: Fixed a use-after-free due to a transfer without a
 reference (bsc#1170901).

CVE-2020-12114: Fixed a pivot_root race condition which could have
 allowed local users to cause a denial of service (panic) by corrupting a
 mountpoint reference counter (bsc#1171098).

CVE-2020-10757: Fixed an issue where remaping hugepage DAX to anon mmap
 could have caused user PTE access (bsc#1172317).

CVE-2020-10751: Fixed an improper implementation in SELinux LSM hook
 where it was assumed that an skb would only contain a single netlink
 message (bsc#1171189).

CVE-2020-10732: Fixed kernel data leak in userspace coredumps due to
 uninitialized data (bsc#1171220).

CVE-2020-10720: Fixed a use-after-free read in napi_gro_frags()
 (bsc#1170778).

CVE-2020-10711: Fixed a null pointer dereference in SELinux subsystem
 which could have allowed a remote network user to crash the kernel
 resulting in a denial of service (bsc#1171191).

CVE-2020-10690: Fixed the race between the release of ptp_clock and cdev
 (bsc#1170056).

CVE-2019-9455: Fixed a pointer leak due to a WARN_ON statement in a
 video driver. This could lead to local information ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 15-SP1, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Development Tools 15-SP1, SUSE Linux Enterprise Module for Legacy Software 15-SP1, SUSE Linux Enterprise Module for Live Patching 15-SP1, SUSE Linux Enterprise Workstation Extension 15-SP1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~197.45.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~197.45.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.12.14~197.45.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.12.14~197.45.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.12.14~197.45.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~197.45.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~4.12.14~197.45.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~197.45.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~197.45.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~197.45.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debuginfo", rpm:"kernel-zfcpdump-debuginfo~4.12.14~197.45.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debugsource", rpm:"kernel-zfcpdump-debugsource~4.12.14~197.45.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.12.14~197.45.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.12.14~197.45.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~4.12.14~197.45.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~197.45.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~197.45.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~4.12.14~197.45.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~4.12.14~197.45.1", rls:"SLES15.0SP1"))) {
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
