# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1173.2");
  script_cve_id("CVE-2017-18257", "CVE-2018-10087", "CVE-2018-10124", "CVE-2018-1087", "CVE-2018-7740", "CVE-2018-8043", "CVE-2018-8781", "CVE-2018-8822", "CVE-2018-8897");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-20 14:00:15 +0000 (Wed, 20 Jun 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1173-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1173-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181173-2.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031717");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057734");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076847");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1077560");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082153");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082299");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085224");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085402");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086162");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086194");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088241");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088684");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089198");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089608");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089752");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090643");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-October/004723.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:1173-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP2 LTSS kernel was updated to 4.4.121 to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2018-8781: The udl_fb_mmap function in drivers/gpu/drm/udl/udl_fb.c had an integer-overflow vulnerability that allowed local users with access to the udldrmfb driver to obtain full read and write permissions on kernel physical pages, resulting in a code execution in kernel space (bnc#1090643).
- CVE-2018-10124: The kill_something_info function in kernel/signal.c might have allowed local users to cause a denial of service via an INT_MIN argument (bnc#1089752).
- CVE-2018-10087: The kernel_wait4 function in kernel/exit.c might have allowed local users to cause a denial of service by triggering an attempted use of the -INT_MIN value (bnc#1089608).
- CVE-2017-18257: The __get_data_block function in fs/f2fs/data.c in the Linux kernel allowed local users to cause a denial of service (integer overflow and loop) via crafted use of the open and fallocate system calls with an FS_IOC_FIEMAP ioctl. (bnc#1088241)
- CVE-2018-8822: Incorrect buffer length handling in the ncp_read_kernel function in fs/ncpfs/ncplib_kernel.c could be exploited by malicious NCPFS servers to crash the kernel or execute code (bnc#1086162).
- CVE-2018-8043: The unimac_mdio_probe function in drivers/net/phy/mdio-bcm-unimac.c did not validate certain resource availability, which allowed local users to cause a denial of service (NULL pointer dereference) (bnc#1084829).
- CVE-2018-7740: The resv_map_release function in mm/hugetlb.c allowed local users to cause a denial of service (BUG) via a crafted application that made mmap system calls and has a large pgoff argument to the remap_file_pages system call (bnc#1084353).
- CVE-2018-1087: And an unprivileged KVM guest user could use this flaw to potentially escalate their privileges inside a guest. (bsc#1087088)
- CVE-2018-8897: An unprivileged system user could use incorrect set up interrupt stacks to crash the Linux kernel resulting in DoS issue. (bsc#1087088)

The following non-security bugs were fixed:

- alsa: hda/realtek - Fix speaker no sound after system resume (bsc#1031717).
- alsa: hda: Add a power_save blacklist (bnc#1012382).
- alsa: usb-audio: Add a quirck for B&W PX headphones (bnc#1012382).
- arm: dts: LogicPD Torpedo: Fix I2C1 pinmux (bnc#1012382).
- arm: mvebu: Fix broken PL310_ERRATA_753970 selects (bnc#1012382).
- kvm: mmu: Fix overlap between public and private memslots (bnc#1012382).
- Partial revert 'e1000e: Avoid receiver overrun interrupt bursts' (bsc#1075428).
- Revert 'e1000e: Separate signaling for link check/link up' (bsc#1075428).
- Revert 'led: core: Fix brightness setting when setting delay_off=0' (bnc#1012382).
- Revert 'watchdog: hpwdt: Remove legacy NMI sourcing (bsc#1085185).' This reverts commit 5d4a2355a2a1c2ec6fdf9d18b68ca0a04ff73c70.
- bpf, x64: implement retpoline for ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.121~92.73.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.121~92.73.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.121~92.73.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.121~92.73.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.121~92.73.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.121~92.73.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.121~92.73.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_73-default", rpm:"kgraft-patch-4_4_121-92_73-default~1~3.3.1", rls:"SLES12.0SP2"))) {
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
