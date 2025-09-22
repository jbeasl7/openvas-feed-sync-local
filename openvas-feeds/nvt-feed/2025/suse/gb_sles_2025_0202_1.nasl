# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0202.1");
  script_cve_id("CVE-2022-49035", "CVE-2023-52524", "CVE-2024-53142", "CVE-2024-53144", "CVE-2024-53146", "CVE-2024-53156", "CVE-2024-53173", "CVE-2024-53179", "CVE-2024-53214", "CVE-2024-53239", "CVE-2024-53240", "CVE-2024-56539", "CVE-2024-56548", "CVE-2024-56604", "CVE-2024-56605", "CVE-2024-56631", "CVE-2024-56704", "CVE-2024-8805");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-20 18:05:47 +0000 (Fri, 20 Dec 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0202-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0202-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250202-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215304");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220927");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220937");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230697");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232436");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234690");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234853");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234921");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234963");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235004");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235054");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235246");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235480");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235584");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-January/020184.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:0202-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2022-49035: media: s5p_cec: limit msg.len to CEC_MAX_MSG_SIZE (bsc#1215304).
- CVE-2024-53146: NFSD: Prevent a potential integer overflow (bsc#1234853).
- CVE-2024-53156: wifi: ath9k: add range check for conn_rsp_epid in htc_connect_service() (bsc#1234846).
- CVE-2024-53173: NFSv4.0: Fix a use-after-free problem in the asynchronous open() (bsc#1234891).
- CVE-2024-53179: smb: client: fix use-after-free of signing key (bsc#1234921).
- CVE-2024-53214: vfio/pci: Properly hide first-in-list PCIe extended capability (bsc#1235004).
- CVE-2024-53239: ALSA: 6fire: Release resources at card release (bsc#1235054).
- CVE-2024-53240: xen/netfront: fix crash when removing device (bsc#1234281).
- CVE-2024-56539: wifi: mwifiex: Fix memcpy() field-spanning write warning in mwifiex_config_scan() (bsc#1234963).
- CVE-2024-56548: hfsplus: do not query the device logical block size multiple times (bsc#1235073).
- CVE-2024-56604: Bluetooth: RFCOMM: avoid leaving dangling sk pointer in rfcomm_sock_alloc() (bsc#1235056).
- CVE-2024-56605: Bluetooth: L2CAP: do not leave dangling sk pointer on error in l2cap_sock_create() (bsc#1235061).
- CVE-2024-56631: scsi: sg: Fix slab-use-after-free read in sg_release() (bsc#1235480).
- CVE-2024-56704: 9p/xen: fix release of IRQ (bsc#1235584).

The following non-security bugs were fixed:

- net: mana: Increase the DEF_RX_BUFFERS_PER_QUEUE to 1024 (bsc#1235246).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.3.18~150300.59.188.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.3.18~150300.59.188.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150300.59.188.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150300.59.188.1.150300.18.111.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150300.59.188.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150300.59.188.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150300.59.188.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150300.59.188.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150300.59.188.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150300.59.188.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150300.59.188.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150300.59.188.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150300.59.188.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.3.18~150300.59.188.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150300.59.188.1", rls:"SLES15.0SP3"))) {
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
