# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.1617.1");
  script_cve_id("CVE-2020-0433", "CVE-2020-1749", "CVE-2020-25670", "CVE-2020-25671", "CVE-2020-25672", "CVE-2020-25673", "CVE-2020-36312", "CVE-2020-36322", "CVE-2021-20219", "CVE-2021-27363", "CVE-2021-27364", "CVE-2021-27365", "CVE-2021-28038", "CVE-2021-28660", "CVE-2021-28950", "CVE-2021-28972", "CVE-2021-29154", "CVE-2021-29264", "CVE-2021-29265", "CVE-2021-29650", "CVE-2021-30002", "CVE-2021-3483");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:38 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-12 03:54:00 +0000 (Mon, 12 Sep 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:1617-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:1617-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20211617-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176720");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178181");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182715");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182717");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183022");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183593");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184167");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184168");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184194");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184198");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184208");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184391");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184393");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184397");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184952");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185556");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185557");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-May/008777.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:1617-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP2 LTSS kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2020-36312: Fixed an issue in virt/kvm/kvm_main.c that had a kvm_io_bus_unregister_dev memory leak upon a kmalloc failure (bnc#1184509).
- CVE-2021-29650: Fixed an issue inside the netfilter subsystem that allowed attackers to cause a denial of service (panic) because net/netfilter/x_tables.c and include/linux/netfilter/x_tables.h lack a full memory barrier upon the assignment of a new table value (bnc#1184208).
- CVE-2021-29154: Fixed BPF JIT compilers that allowed to execute arbitrary code within the kernel context (bnc#1184391).
- CVE-2020-25673: Fixed NFC endless loops caused by repeated llcp_sock_connect() (bsc#1178181).
- CVE-2020-25672: Fixed NFC memory leak in llcp_sock_connect() (bsc#1178181).
- CVE-2020-25671: Fixed NFC refcount leak in llcp_sock_connect() (bsc#1178181).
- CVE-2020-25670: Fixed NFC refcount leak in llcp_sock_bind() (bsc#1178181).
- CVE-2021-28950: Fixed an issue in fs/fuse/fuse_i.h where a 'stall on CPU' could have occurred because a retry loop continually finds the same bad inode (bnc#1184194, bnc#1184211).
- CVE-2021-30002: Fixed a memory leak issue when a webcam device exists (bnc#1184120).
- CVE-2021-3483: Fixed a use-after-free bug in nosy_ioctl() (bsc#1184393).
- CVE-2021-20219: Fixed a denial of service vulnerability in drivers/tty/n_tty.c of the Linux kernel. In this flaw a local attacker with a normal user privilege could have delayed the loop and cause a threat to the system availability (bnc#1184397).
- CVE-2021-29265: Fixed an issue in usbip_sockfd_store in drivers/usb/usbip/stub_dev.c that allowed attackers to cause a denial of service (GPF) because the stub-up sequence has race conditions during an update of the local and shared status (bnc#1184167).
- CVE-2021-29264: Fixed an issue in drivers/net/ethernet/freescale/gianfar.c in the Freescale Gianfar Ethernet driver that allowed attackers to cause a system crash because a negative fragment size is calculated in situations involving an rx queue overrun when jumbo packets are used and NAPI is enabled (bnc#1184168).
- CVE-2021-28972: Fixed an issue in drivers/pci/hotplug/rpadlpar_sysfs.c where the RPA PCI Hotplug driver had a user-tolerable buffer overflow when writing a new device name to the driver from userspace, allowing userspace to write data to the kernel stack frame directly. This occurs because add_slot_store and remove_slot_store mishandle drc_name '\0' termination (bnc#1184198).
- CVE-2021-28660: Fixed rtw_wx_set_scan in drivers/staging/rtl8188eu/os_dep/ioctl_linux.c that allowed writing beyond the end of the ssid array (bnc#1183593).
- CVE-2020-0433: Fixed blk_mq_queue_tag_busy_iter of blk-mq-tag.c, where a possible use after free due to improper locking could have happened. This could have led to local escalation of privilege ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.121~92.155.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.121~92.155.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.121~92.155.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.121~92.155.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.121~92.155.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.121~92.155.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.121~92.155.1", rls:"SLES12.0SP2"))) {
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
