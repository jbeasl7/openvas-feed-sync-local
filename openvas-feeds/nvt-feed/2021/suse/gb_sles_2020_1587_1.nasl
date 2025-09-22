# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1587.1");
  script_cve_id("CVE-2018-1000199", "CVE-2019-19462", "CVE-2019-20806", "CVE-2019-20812", "CVE-2019-9455", "CVE-2020-0543", "CVE-2020-10690", "CVE-2020-10711", "CVE-2020-10720", "CVE-2020-10732", "CVE-2020-10751", "CVE-2020-10757", "CVE-2020-12114", "CVE-2020-12464", "CVE-2020-12652", "CVE-2020-12653", "CVE-2020-12654", "CVE-2020-12655", "CVE-2020-12656", "CVE-2020-12657", "CVE-2020-12659", "CVE-2020-12768", "CVE-2020-12769", "CVE-2020-13143");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-07 20:57:04 +0000 (Thu, 07 May 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1587-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1587-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201587-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103991");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113956");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124278");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127371");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141558");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142685");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151794");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152489");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158265");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160388");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160947");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165478");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165741");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166978");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1167574");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1167851");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1167867");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168503");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168670");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168789");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169005");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169020");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169525");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169762");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170284");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170345");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170457");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170522");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170592");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170621");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170778");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170791");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171098");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171118");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171205");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171214");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171218");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171219");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171417");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171599");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171601");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171602");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171604");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171605");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171606");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171607");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171608");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171609");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171613");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171614");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171616");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171619");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171621");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171622");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171623");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171624");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171625");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171626");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171662");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171679");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171691");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171692");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171694");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171695");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171736");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171761");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171817");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171949");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171951");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171952");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172017");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172096");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172097");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172098");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172099");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172101");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172102");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172103");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172104");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172127");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172130");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172188");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172201");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172218");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172249");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172251");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172253");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172342");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172343");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172344");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172366");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172391");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172397");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172453");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-June/006912.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:1587-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2020-0543: Fixed a side channel attack against special registers which could have resulted in leaking of read values to cores other than the one which called it.
 This attack is known as Special Register Buffer Data Sampling (SRBDS) or 'CrossTalk' (bsc#1154824).
- CVE-2020-13143: Fixed an out-of-bounds read in gadget_dev_desc_UDC_store in drivers/usb/gadget/configfs.c (bsc#1171982).
- CVE-2020-12769: Fixed an issue which could have allowed attackers to cause a panic via concurrent calls to dw_spi_irq and dw_spi_transfer_one (bsc#1171983).
- CVE-2020-12768: Fixed a memory leak in svm_cpu_uninit in arch/x86/kvm/svm.c (bsc#1171736).
- CVE-2020-12659: Fixed an out-of-bounds write (by a user with the CAP_NET_ADMIN capability) due to improper headroom validation (bsc#1171214).
- CVE-2020-12657: An a use-after-free in block/bfq-iosched.c (bsc#1171205).
- CVE-2020-12656: Fixed an improper handling of certain domain_release calls leadingch could have led to a memory leak (bsc#1171219).
- CVE-2020-12655: Fixed an issue which could have allowed attackers to trigger a sync of excessive duration via an XFS v5 image with crafted metadata (bsc#1171217).
- CVE-2020-12654: Fixed an issue in he wifi driver which could have allowed a remote AP to trigger a heap-based buffer overflow (bsc#1171202).
- CVE-2020-12653: Fixed an issue in the wifi driver which could have allowed local users to gain privileges or cause a denial of service (bsc#1171195).
- CVE-2020-12652: Fixed an issue which could have allowed local users to hold an incorrect lock during the ioctl operation and trigger a race condition (bsc#1171218).
- CVE-2020-12464: Fixed a use-after-free due to a transfer without a reference (bsc#1170901).
- CVE-2020-12114: Fixed a pivot_root race condition which could have allowed local users to cause a denial of service (panic) by corrupting a mountpoint reference counter (bsc#1171098).
- CVE-2020-10757: Fixed an issue where remaping hugepage DAX to anon mmap could have caused user PTE access (bsc#1172317).
- CVE-2020-10751: Fixed an improper implementation in SELinux LSM hook where it was assumed that an skb would only contain a single netlink message (bsc#1171189).
- CVE-2020-10732: Fixed kernel data leak in userspace coredumps due to uninitialized data (bsc#1171220).
- CVE-2020-10720: Fixed a use-after-free read in napi_gro_frags() (bsc#1170778).
- CVE-2020-10711: Fixed a null pointer dereference in SELinux subsystem which could have allowed a remote network user to crash the kernel resulting in a denial of service (bsc#1171191).
- CVE-2020-10690: Fixed the race between the release of ptp_clock and cdev (bsc#1170056).
- CVE-2019-9455: Fixed a pointer leak due to a WARN_ON statement in a video driver. This could lead to local information ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.16.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.16.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.16.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.16.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.16.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.16.1", rls:"SLES12.0SP5"))) {
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
