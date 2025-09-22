# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.4346.1");
  script_cve_id("CVE-2023-52922", "CVE-2024-26782", "CVE-2024-44932", "CVE-2024-44964", "CVE-2024-47757", "CVE-2024-50017", "CVE-2024-50089", "CVE-2024-50115", "CVE-2024-50125", "CVE-2024-50127", "CVE-2024-50154", "CVE-2024-50205", "CVE-2024-50259", "CVE-2024-50264", "CVE-2024-50267", "CVE-2024-50274", "CVE-2024-50279", "CVE-2024-50290", "CVE-2024-50301", "CVE-2024-50302", "CVE-2024-53061", "CVE-2024-53063", "CVE-2024-53068");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-25 13:43:00 +0000 (Mon, 25 Nov 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:4346-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4346-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20244346-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222590");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229808");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231646");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232187");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232312");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232860");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232919");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232928");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233214");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233453");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233468");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233479");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233490");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233491");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233557");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233561");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233977");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-December/020017.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:4346-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various security bugfixes.

The following security bugs were fixed:

- CVE-2024-26782: mptcp: fix double-free on socket dismantle (bsc#1222590).
- CVE-2024-44932: idpf: fix UAFs when destroying the queues (bsc#1229808).
- CVE-2024-44964: idpf: fix memory leaks and crashes while performing a soft reset (bsc#1230220).
- CVE-2024-47757: nilfs2: fix potential oob read in nilfs_btree_check_delete() (bsc#1232187).
- CVE-2024-50089: unicode: Do not special case ignorable code points (bsc#1232860).
- CVE-2024-50115: KVM: nSVM: Ignore nCR3[4:0] when loading PDPTEs from memory (bsc#1232919).
- CVE-2024-50125: Bluetooth: SCO: Fix UAF on sco_sock_timeout (bsc#1232928).
- CVE-2024-50127: net: sched: fix use-after-free in taprio_change() (bsc#1232907).
- CVE-2024-50154: tcp: Fix use-after-free of nreq in reqsk_timer_handler() (bsc#1233070).
- CVE-2024-50205: ALSA: firewire-lib: Avoid division by zero in apply_constraint_to_size() (bsc#1233293).
- CVE-2024-50259: netdevsim: Add trailing zero to terminate the string in nsim_nexthop_bucket_activity_write() (bsc#1233214).
- CVE-2024-50264: vsock/virtio: Initialization of the dangling pointer occurring in vsk->trans (bsc#1233453).
- CVE-2024-50267: USB: serial: io_edgeport: fix use after free in debug printk (bsc#1233456).
- CVE-2024-50274: idpf: avoid vport access in idpf_get_link_ksettings (bsc#1233463).
- CVE-2024-50279: dm cache: fix out-of-bounds access to the dirty bitset when resizing (bsc#1233468).
- CVE-2024-50290: media: cx24116: prevent overflows on SNR calculus (bsc#1233479).
- CVE-2024-50301: security/keys: fix slab-out-of-bounds in key_task_permission (bsc#1233490).
- CVE-2024-50302: HID: core: zero-initialize the report buffer (bsc#1233491).
- CVE-2024-53061: media: s5p-jpeg: prevent buffer overflows (bsc#1233555).
- CVE-2024-53063: media: dvbdev: prevent the risk of out of memory access (bsc#1233557).
- CVE-2024-53068: firmware: arm_scmi: Fix slab-use-after-free in scmi_bus_notifier() (bsc#1233561).

The following non-security bugs were fixed:

- Update config files (bsc#1218644).
- Update config files. Enabled IDPF for ARM64 (bsc#1221309)
- kernel-binary: Enable livepatch package only when livepatch is enabled Otherwise the filelist may be empty failing the build (bsc#1218644).
- mm/memory: add non-anonymous page check in the copy_present_page() (bsc#1231646).
- rpm/scripts: Remove obsolete Symbols.list Symbols.list is not longer needed by the new klp-convert implementation. (bsc#1218644)");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150400.24.144.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150400.24.144.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150400.24.144.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150400.24.144.1.150400.24.70.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150400.24.144.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150400.24.144.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150400.24.144.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150400.24.144.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150400.24.144.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150400.24.144.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150400.24.144.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150400.24.144.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150400.24.144.1", rls:"SLES15.0SP4"))) {
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
