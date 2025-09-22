# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1196.1");
  script_cve_id("CVE-2021-39713", "CVE-2021-45868", "CVE-2022-0001", "CVE-2022-0002", "CVE-2022-0812", "CVE-2022-0850", "CVE-2022-1016", "CVE-2022-1048", "CVE-2022-23036", "CVE-2022-23037", "CVE-2022-23038", "CVE-2022-23039", "CVE-2022-23040", "CVE-2022-23041", "CVE-2022-23042", "CVE-2022-23960", "CVE-2022-26490", "CVE-2022-26966", "CVE-2022-27666", "CVE-2022-28388", "CVE-2022-28389", "CVE-2022-28390");
  script_tag(name:"creation_date", value:"2022-04-15 04:28:02 +0000 (Fri, 15 Apr 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-11 14:45:16 +0000 (Wed, 11 May 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1196-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1196-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221196-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114648");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180153");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184207");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191451");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192273");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194163");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194541");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194586");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194590");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194591");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194943");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195403");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195480");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196114");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196339");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196367");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196468");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196478");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196488");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196639");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196657");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196761");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196973");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196999");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197099");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197227");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197331");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197366");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197462");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197531");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197661");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197675");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197754");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197755");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197756");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197760");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197763");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197894");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197914");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198031");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198033");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-April/010723.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:1196-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated.

The following security bugs were fixed:

- CVE-2022-1016: Fixed a vulnerability in the nf_tables component of the netfilter subsystem. This vulnerability gives an attacker a powerful primitive that can be used to both read from and write to relative stack data, which can lead to arbitrary code execution. (bsc#1197227)
- CVE-2022-28389: Fixed a double free in drivers/net/can/usb/mcba_usb.c vulnerability in the Linux kernel. (bnc#1198033)
- CVE-2022-28390: Fixed a double free in drivers/net/can/usb/ems_usb.c vulnerability in the Linux kernel. (bnc#1198031)
- CVE-2022-28388: Fixed a double free in drivers/net/can/usb/usb_8dev.c vulnerability in the Linux kernel. (bnc#1198032)
- CVE-2022-0812: Fixed an incorrect header size calculations which could lead to a memory leak. (bsc#1196639)
- CVE-2022-1048: Fixed a race Condition in snd_pcm_hw_free leading to use-after-free due to the AB/BA lock with buffer_mutex and mmap_lock. (bsc#1197331)
- CVE-2022-0850: Fixed a kernel information leak vulnerability in iov_iter.c. (bsc#1196761)
- CVE-2022-26966: Fixed an issue in drivers/net/usb/sr9700.c, which allowed attackers to obtain sensitive information from the memory via crafted frame lengths from a USB device. (bsc#1196836)
- CVE-2021-45868: Fixed a wrong validation check in fs/quota/quota_tree.c which could lead to an use-after-free if there is a corrupted quota file. (bnc#1197366)
- CVE-2021-39713: Fixed a race condition in the network scheduling subsystem which could lead to a use-after-free. (bnc#1196973)
- CVE-2022-23036,CVE-2022-23037,CVE-2022-23038,CVE-2022-23039,CVE-2022-23040,CVE-2022-23041,CVE-2022-23042: Fixed multiple issues which could have lead to read/write access to memory pages or denial of service. These issues are related to the Xen PV device frontend drivers. (bsc#1196488)
- CVE-2022-26490: Fixed a buffer overflow in the st21nfca driver. An attacker with adjacent NFC access could crash the system or corrupt the system memory. (bsc#1196830)
- CVE-2022-0001,CVE-2022-0002,CVE-2022-23960: Fixed a new kind of speculation issues, exploitable via JITed eBPF for instance. (bsc#1191580)
- CVE-2022-27666: Fixed a buffer overflow vulnerability in IPsec ESP transformation code. This flaw allowed a local attacker with a normal user privilege to overwrite kernel heap objects and may cause a local privilege escalation. (bnc#1197462)

The following non-security bugs were fixed:

- asix: Add rx->ax_skb = NULL after usbnet_skb_return() (git-fixes).
- asix: Ensure asix_rx_fixup_info members are all reset (git-fixes).
- asix: Fix small memory leak in ax88772_unbind() (git-fixes).
- asix: fix uninit-value in asix_mdio_read() (git-fixes).
- asix: fix wrong return value in asix_check_host_enable() (git-fixes).
- ax88179_178a: Merge memcpy + le32_to_cpus to get_unaligned_le32 (bsc#1196018).
- block: bfq: fix bfq_set_next_ioprio_data() ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.116.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.116.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.116.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.116.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.116.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.116.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.116.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.116.1", rls:"SLES12.0SP5"))) {
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
