# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2948.1");
  script_cve_id("CVE-2018-12207", "CVE-2019-0154", "CVE-2019-0155", "CVE-2019-10220", "CVE-2019-11135", "CVE-2019-16233");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-16 21:05:12 +0000 (Mon, 16 Dec 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2948-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2948-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192948-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096254");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117665");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119461");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119465");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123034");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135966");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138190");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1139073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140090");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150457");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151225");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152624");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153476");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154737");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154848");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154905");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155184");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155671");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-November/006109.html");
  script_xref(name:"URL", value:"https://www.suse.com/support/kb/doc/?id=7023735");
  script_xref(name:"URL", value:"https://www.suse.com/support/kb/doc/?id=7024251");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:2948-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP4 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2018-12207: Untrusted virtual machines on Intel CPUs could exploit a race condition in the Instruction Fetch Unit of the Intel CPU to cause a Machine Exception during Page Size Change, causing the CPU core to be non-functional.

The Linux Kernel KVM hypervisor was adjusted to avoid page size changes in executable pages by splitting / merging huge pages into small pages as needed.
More information can be found on [link moved to references]

CVE-2019-11135: Aborting an asynchronous TSX operation on Intel CPUs with Transactional Memory support could be used to facilitate sidechannel information leaks out of microarchitectural buffers, similar to the previously described 'Microarchitectural Data Sampling' attack.

The Linux kernel was supplemented with the option to disable TSX operation altogether (requiring CPU Microcode updates on older systems) and better flushing of microarchitectural buffers (VERW).

The set of options available is described in our TID at [link moved to references]

Other security fixes:

- CVE-2019-0154: Fixed a local denial of service via read of unprotected i915 registers. (bsc#1135966)
- CVE-2019-0155: Fixed privilege escalation in the i915 driver. Batch buffers from usermode could have escalated privileges via blitter command stream. (bsc#1135967)
- CVE-2019-16233: drivers/scsi/qla2xxx/qla_os.c did not check the alloc_workqueue return value, leading to a NULL pointer dereference. (bsc#1150457).
- CVE-2019-10220: Added sanity checks on the pathnames passed to the user space. (bsc#1144903).

The following non-security bugs were fixed:

- alsa: bebob: Fix prototype of helper function to return negative value (bsc#1051510).
- alsa: hda/realtek - Add support for ALC623 (bsc#1051510).
- alsa: hda/realtek - Add support for ALC711 (bsc#1051510).
- alsa: hda/realtek - Fix 2 front mics of codec 0x623 (bsc#1051510).
- alsa: hda: Add Elkhart Lake PCI ID (bsc#1051510).
- alsa: hda: Add Tigerlake/Jasperlake PCI ID (bsc#1051510).
- alsa: timer: Fix mutex deadlock at releasing card (bsc#1051510).
- arcnet: provide a buffer big enough to actually receive packets (networking-stable-19_09_30).
- asoc: rockchip: i2s: Fix RPM imbalance (bsc#1051510).
- asoc: rsnd: Reinitialize bit clock inversion flag for every format setting (bsc#1051510).
- bpf: fix use after free in prog symbol exposure (bsc#1083647).
- btrfs: block-group: Fix a memory leak due to missing btrfs_put_block_group() (bsc#1155178).
- btrfs: qgroup: Always free PREALLOC META reserve in btrfs_delalloc_release_extents() (bsc#1155179).
- btrfs: tracepoints: Fix bad entry members of qgroup events (bsc#1155186).
- btrfs: tracepoints: Fix wrong parameter order for qgroup events (bsc#1155184).
- crypto: af_alg - Fix race around ctx->rcvused by making it atomic_t ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~95.40.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~95.40.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~95.40.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~95.40.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~95.40.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~95.40.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~95.40.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~95.40.1", rls:"SLES12.0SP4"))) {
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
