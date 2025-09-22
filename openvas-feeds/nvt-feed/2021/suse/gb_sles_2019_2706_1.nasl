# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2706.1");
  script_cve_id("CVE-2017-18595", "CVE-2019-14821", "CVE-2019-15291", "CVE-2019-9506");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:15 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-20 13:01:35 +0000 (Fri, 20 Sep 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2706-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2706-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192706-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:2706-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:
CVE-2019-15291: There was a NULL pointer dereference, caused by a
 malicious USB device in the flexcop_usb_probe function in the
 drivers/media/usb/b2c2/flexcop-usb.c driver (bnc#1146540).

CVE-2019-14821: An out-of-bounds access issue was found in the way the
 KVM hypervisor implements the Coalesced MMIO write operation. It
 operates on an MMIO ring buffer 'struct kvm_coalesced_mmio' object,
 wherein write indices 'ring->first' and 'ring->last' value could be
 supplied by a host user-space process. An unprivileged host user or
 process with access to '/dev/kvm' device could use this flaw to crash
 the host kernel, resulting in a denial of service or potentially
 escalating privileges on the system (bnc#1151350).

CVE-2017-18595: A double free may be caused by the function
 allocate_trace_buffer in the file kernel/trace/trace.c (bnc#1149555).

CVE-2019-9506: The Bluetooth BR/EDR specification up to and including
 version 5.1 permitted sufficiently low encryption key length and did not
 prevent an attacker from influencing the key length negotiation. This
 allowed practical brute-force attacks (aka 'KNOB') that could decrypt
 traffic and injected arbitrary ciphertext without the victim noticing
 (bnc#1137865 bnc#1146042).

The following non-security bugs were fixed:
ACPI: custom_method: fix memory leaks (bsc#1051510).

ACPI / PCI: fix acpi_pci_irq_enable() memory leak (bsc#1051510).

ACPI / property: Fix acpi_graph_get_remote_endpoint() name in kerneldoc
 (bsc#1051510).

alarmtimer: Use EOPNOTSUPP instead of ENOTSUPP (bsc#1151680).

ALSA: aoa: onyx: always initialize register read value (bsc#1051510).

ALSA: firewire-tascam: check intermediate state of clock status and
 retry (bsc#1051510).

ALSA: firewire-tascam: handle error code when getting current source of
 clock (bsc#1051510).

ASoC: es8328: Fix copy-paste error in es8328_right_line_controls
 (bsc#1051510).

ASoC: Intel: Baytrail: Fix implicit fallthrough warning (bsc#1051510).

ASoC: sun4i-i2s: RX and TX counter registers are swapped (bsc#1051510).

ASoC: wm8737: Fix copy-paste error in wm8737_snd_controls (bsc#1051510).

ASoC: wm8988: fix typo in wm8988_right_line_controls (bsc#1051510).

ath9k: dynack: fix possible deadlock in ath_dynack_node_{de}init
 (bsc#1051510).

atm: iphase: Fix Spectre v1 vulnerability (networking-stable-19_08_08).

bcma: fix incorrect update of BCMA_CORE_PCI_MDIO_DATA (bsc#1051510).

blk-flush: do not run queue for requests bypassing flush (bsc#1137959).

blk-flush: use blk_mq_request_bypass_insert() (bsc#1137959).

blk-mq: do not allocate driver tag upfront for flush rq (bsc#1137959).

blk-mq: Fix memory leak in blk_mq_init_allocated_queue error handling
 (bsc#1151610).

blk-mq: insert rq with DONTPREP to hctx dispatch list when requeue
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 15, SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Development Tools 15, SUSE Linux Enterprise Module for Legacy Software 15, SUSE Linux Enterprise Module for Live Patching 15, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15, SUSE Linux Enterprise Workstation Extension 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~150.38.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~150.38.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.12.14~150.38.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.12.14~150.38.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~150.38.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~4.12.14~150.38.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~150.38.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~150.38.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~150.38.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~4.12.14~150.38.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debuginfo", rpm:"kernel-zfcpdump-debuginfo~4.12.14~150.38.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debugsource", rpm:"kernel-zfcpdump-debugsource~4.12.14~150.38.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.12.14~150.38.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.12.14~150.38.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~4.12.14~150.38.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~150.38.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~150.38.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base", rpm:"kernel-vanilla-base~4.12.14~150.38.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base-debuginfo", rpm:"kernel-vanilla-base-debuginfo~4.12.14~150.38.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debuginfo", rpm:"kernel-vanilla-debuginfo~4.12.14~150.38.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debugsource", rpm:"kernel-vanilla-debugsource~4.12.14~150.38.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~4.12.14~150.38.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~4.12.14~150.38.1", rls:"SLES15.0"))) {
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
