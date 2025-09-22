# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1772.1");
  script_cve_id("CVE-2017-17741", "CVE-2017-18241", "CVE-2017-18249", "CVE-2018-12233", "CVE-2018-3665", "CVE-2018-5848");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-09 19:12:31 +0000 (Fri, 09 Feb 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1772-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1772-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181772-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024718");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031717");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035432");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1041740");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056415");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068054");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068951");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073311");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076049");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078583");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1079152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080542");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080656");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1081500");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1081514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082153");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082504");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085308");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087086");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090435");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090534");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090734");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090955");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1091594");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094532");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1095042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1095147");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096037");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096214");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096751");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097234");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097356");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1098009");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1098012");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971975");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978907");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-June/004211.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:1772-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP3 kernel was updated to 4.4.136 to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2018-5848: In the function wmi_set_ie(), the length validation code did
 not handle unsigned integer overflow properly. As a result, a large value of
 the 'ie_len' argument could have caused a buffer overflow (bnc#1097356).
- CVE-2017-18249: The add_free_nid function did not properly track an allocated
 nid, which allowed local users to cause a denial of service (race condition) or
 possibly have unspecified other impact via concurrent threads (bnc#1087036).
- CVE-2018-3665: Prevent disclosure of FPU registers (including XMM and AVX
 registers) between processes. These registers might contain encryption keys
 when doing SSE accelerated AES enc/decryption (bsc#1087086).
- CVE-2017-18241: Prevent a NULL pointer dereference by using a noflush_merge
 option that triggers a NULL value for a flush_cmd_control data structure
 (bnc#1086400).
- CVE-2017-17741: The KVM implementation in the Linux kernel allowed attackers
 to obtain potentially sensitive information from kernel memory, aka a
 write_mmio stack-based out-of-bounds read (bnc#1073311).
- CVE-2018-12233: In the ea_get function in fs/jfs/xattr.c, a memory
 corruption bug in JFS can be triggered by calling setxattr twice with two
 different extended attribute names on the same file. This vulnerability
 can be triggered by an unprivileged user with the ability to create
 files and execute programs. A kmalloc call is incorrect, leading to
 slab-out-of-bounds in jfs_xattr (bnc#1097234).

The following non-security bugs were fixed:

- 8139too: Use disable_irq_nosync() in rtl8139_poll_controller() (bnc#1012382).
- ACPI: acpi_pad: Fix memory leak in power saving threads (bnc#1012382).
- ACPICA: acpi: acpica: fix acpi operand cache leak in nseval.c (bnc#1012382).
- ACPICA: Events: add a return on failure from acpi_hw_register_read (bnc#1012382).
- ACPI: processor_perflib: Do not send _PPC change notification if not ready (bnc#1012382).
- affs_lookup(): close a race with affs_remove_link() (bnc#1012382).
- af_key: Always verify length of provided sadb_key (bnc#1012382).
- aio: fix io_destroy(2) vs. lookup_ioctx() race (bnc#1012382).
- alsa: control: fix a redundant-copy issue (bnc#1012382).
- alsa: hda: Add Lenovo C50 All in one to the power_save blacklist (bnc#1012382).
- alsa: hda - Use IS_REACHABLE() for dependency on input (bnc#1012382 bsc#1031717).
- alsa: timer: Call notifier in the same spinlock (bnc#1012382 bsc#973378).
- alsa: timer: Fix pause event notification (bnc#1012382 bsc#973378).
- alsa: usb: mixer: volume quirk for CM102-A+/102S+ (bnc#1012382).
- alsa: vmaster: Propagate slave error (bnc#1012382).
- arc: Fix malformed ARC_EMUL_UNALIGNED default (bnc#1012382).
- arm64: Add ARCH_WORKAROUND_2 probing (bsc#1085308).
- arm64: Add per-cpu infrastructure to call ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.138~94.39.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.138~94.39.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.138~94.39.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.138~94.39.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.138~94.39.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.138~94.39.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.138~94.39.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.138~94.39.1", rls:"SLES12.0SP3"))) {
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
