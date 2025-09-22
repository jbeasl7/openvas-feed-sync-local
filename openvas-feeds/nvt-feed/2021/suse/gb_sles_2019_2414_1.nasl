# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2414.1");
  script_cve_id("CVE-2017-18551", "CVE-2018-20976", "CVE-2018-21008", "CVE-2019-10207", "CVE-2019-14814", "CVE-2019-14815", "CVE-2019-14816", "CVE-2019-14835", "CVE-2019-15030", "CVE-2019-15031", "CVE-2019-15090", "CVE-2019-15098", "CVE-2019-15117", "CVE-2019-15118", "CVE-2019-15211", "CVE-2019-15212", "CVE-2019-15214", "CVE-2019-15215", "CVE-2019-15216", "CVE-2019-15217", "CVE-2019-15218", "CVE-2019-15219", "CVE-2019-15220", "CVE-2019-15221", "CVE-2019-15222", "CVE-2019-15239", "CVE-2019-15290", "CVE-2019-15292", "CVE-2019-15538", "CVE-2019-15666", "CVE-2019-15902", "CVE-2019-15917", "CVE-2019-15919", "CVE-2019-15920", "CVE-2019-15921", "CVE-2019-15924", "CVE-2019-15926", "CVE-2019-15927", "CVE-2019-9456");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:19 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-05 13:21:05 +0000 (Thu, 05 Sep 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2414-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2414-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192414-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:2414-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 kernel was updated to receive various security and bugfixes.

The following new features were implemented:
jsc#SLE-4875: [CML] New device IDs for CML

jsc#SLE-7294: Add cpufreq driver for Raspberry Pi

fate#321840: Reduce memory required to boot capture kernel while using
 fadump

fate#326869: perf: pmu mem_load/store event support

fate:327775: vpmem: DRAM backed persistent volumes for improved SAP HANA
 on POWER restart times

The following security bugs were fixed:
CVE-2019-14814, CVE-2019-14815, CVE-2019-14816: Fix three heap-based
 buffer overflows in marvell wifi chip driver kernel, that allowed local
 users to cause a denial of service (system crash) or possibly execute
 arbitrary code. (bnc#1146516)

CVE-2019-15216: Fix a NULL pointer dereference caused by a malicious USB
 device in the drivers/usb/misc/yurex.c driver. (bsc#1146361).

CVE-2019-14835: Fix QEMU-KVM Guest to Host Kernel Escape. (bsc#1150112).

CVE-2019-15924: Fix a NULL pointer dereference because there was no
 -ENOMEM upon an alloc_workqueue failure. (bsc#1149612).

CVE-2019-9456: In Pixel C USB monitor driver there was a possible OOB
 write due to a missing bounds check. This could have lead to local
 escalation of privilege with System execution privileges needed.
 (bsc#1150025 CVE-2019-9456).

CVE-2019-15030, CVE-2019-15031: On the powerpc platform, a local user
 could read vector registers of other users' processes via an interrupt.
 (bsc#1149713)

CVE-2019-15920: SMB2_read in fs/cifs/smb2pdu.c had a use-after-free.
 (bsc#1149626)

CVE-2019-15921: There was a memory leak issue when idr_alloc() failed
 (bsc#1149602)

CVE-2018-21008: A use-after-free can be caused by the function
 rsi_mac80211_detach (bsc#1149591).

CVE-2019-15919: SMB2_write in fs/cifs/smb2pdu.c had a use-after-free.
 (bsc#1149552)

CVE-2019-15917: There was a use-after-free issue when
 hci_uart_register_dev() failed in hci_uart_set_proto() (bsc#1149539)

CVE-2019-15926: Out of bounds access existed in the functions
 ath6kl_wmi_pstream_timeout_event_rx and ath6kl_wmi_cac_event_rx
 (bsc#1149527)

CVE-2019-15927: An out-of-bounds access existed in the function
 build_audio_procunit (bsc#1149522)

CVE-2019-15902: A backporting error reintroduced the Spectre
 vulnerability that it aimed to eliminate. (bnc#1149376)

CVE-2019-15666: There was an out-of-bounds array access in
 __xfrm_policy_unlink, which would cause denial of service, because
 verify_newpolicy_info mishandled directory validation. (bsc#1148394).

CVE-2019-15219: There was a NULL pointer dereference caused by a
 malicious USB device in the drivers/usb/misc/sisusbvga/sisusb.c driver.
 (bsc#1146524)

CVE-2019-15220: There was a use-after-free caused by a malicious USB
 device in the drivers/net/wireless/intersil/p54/p54usb.c driver.
 (bsc#1146526)

CVE-2019-15538: XFS partially wedged when a chgrp failed on account of
 being out of disk quota. ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~150.35.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~150.35.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.12.14~150.35.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.12.14~150.35.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~150.35.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~4.12.14~150.35.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~150.35.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~150.35.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~150.35.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~4.12.14~150.35.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debuginfo", rpm:"kernel-zfcpdump-debuginfo~4.12.14~150.35.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debugsource", rpm:"kernel-zfcpdump-debugsource~4.12.14~150.35.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.12.14~150.35.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.12.14~150.35.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~4.12.14~150.35.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~150.35.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~150.35.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base", rpm:"kernel-vanilla-base~4.12.14~150.35.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base-debuginfo", rpm:"kernel-vanilla-base-debuginfo~4.12.14~150.35.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debuginfo", rpm:"kernel-vanilla-debuginfo~4.12.14~150.35.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debugsource", rpm:"kernel-vanilla-debugsource~4.12.14~150.35.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~4.12.14~150.35.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~4.12.14~150.35.1", rls:"SLES15.0"))) {
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
