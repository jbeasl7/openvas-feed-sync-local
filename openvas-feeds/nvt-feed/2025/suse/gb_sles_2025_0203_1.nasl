# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0203.1");
  script_cve_id("CVE-2021-47202", "CVE-2022-49035", "CVE-2024-41087", "CVE-2024-50154", "CVE-2024-53095", "CVE-2024-53142", "CVE-2024-53146", "CVE-2024-53156", "CVE-2024-53173", "CVE-2024-53179", "CVE-2024-53206", "CVE-2024-53214", "CVE-2024-53239", "CVE-2024-53240", "CVE-2024-53241", "CVE-2024-56539", "CVE-2024-56548", "CVE-2024-56570", "CVE-2024-56598", "CVE-2024-56604", "CVE-2024-56605", "CVE-2024-56619", "CVE-2024-8805");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-20 18:05:47 +0000 (Fri, 20 Dec 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0203-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0203-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250203-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173139");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190358");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209798");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215304");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228466");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230697");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232436");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233642");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234853");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234921");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234963");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235004");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235054");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235224");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235246");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235507");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-January/020183.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:0203-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2024-41087: Fix double free on error (bsc#1228466).
- CVE-2024-53095: smb: client: Fix use-after-free of network namespace (bsc#1233642).
- CVE-2024-53146: NFSD: Prevent a potential integer overflow (bsc#1234853).
- CVE-2024-53156: wifi: ath9k: add range check for conn_rsp_epid in htc_connect_service() (bsc#1234846).
- CVE-2024-53173: NFSv4.0: Fix a use-after-free problem in the asynchronous open() (bsc#1234891).
- CVE-2024-53179: smb: client: fix use-after-free of signing key (bsc#1234921).
- CVE-2024-53214: vfio/pci: Properly hide first-in-list PCIe extended capability (bsc#1235004).
- CVE-2024-53239: ALSA: 6fire: Release resources at card release (bsc#1235054).
- CVE-2024-53240: xen/netfront: fix crash when removing device (bsc#1234281).
- CVE-2024-53241: x86/xen: use new hypercall functions instead of hypercall page (XSA-466 bsc#1234282).
- CVE-2024-56539: wifi: mwifiex: Fix memcpy() field-spanning write warning in mwifiex_config_scan() (bsc#1234963).
- CVE-2024-56548: hfsplus: do not query the device logical block size multiple times (bsc#1235073).
- CVE-2024-56570: ovl: Filter invalid inodes with missing lookup function (bsc#1235035).
- CVE-2024-56598: jfs: array-index-out-of-bounds fix in dtReadFirst (bsc#1235220).
- CVE-2024-56604: Bluetooth: RFCOMM: avoid leaving dangling sk pointer in rfcomm_sock_alloc() (bsc#1235056).
- CVE-2024-56605: Bluetooth: L2CAP: do not leave dangling sk pointer on error in l2cap_sock_create() (bsc#1235061).
- CVE-2024-56619: nilfs2: fix potential out-of-bounds memory access in nilfs_find_entry() (bsc#1235224).
- CVE-2024-8805: Bluetooth: hci_event: Align BR/EDR JUST_WORKS paring with LE (bsc#1230697).

The following non-security bugs were fixed:

- Drop a couple of block layer git-fixes (bsc#1170891 bsc#1173139)
- KVM: x86: fix sending PV IPI (git-fixes).
- fixup 'rpm: support gz and zst compression methods' once more (bsc#1190428, bsc#1190358)
- idpf: add support for SW triggered interrupts (bsc#1235507).
- idpf: enable WB_ON_ITR (bsc#1235507).
- idpf: trigger SW interrupt when exiting wb_on_itr mode (bsc#1235507).
- kernel-binary: do not BuildIgnore m4. It is actually needed for regenerating zconf when it is not up-to-date due to merge.
- net: mana: Increase the DEF_RX_BUFFERS_PER_QUEUE to 1024 (bsc#1235246).
- rpm/kernel-binary.spec.in: Fix build regression The previous fix forgot to take over grep -c option that broke the conditional expression
- scsi: storvsc: Do not flag MAINTENANCE_IN return of SRB_STATUS_DATA_OVERRUN as an error (git-fixes).
- smb: client: fix TCP timers deadlock after rmmod (git-fixes) [hcarvalho: this fixes issue discussed in bsc#1233642].
- supported.conf: add bsc1185010 dependency
- supported.conf: hyperv_drm (jsc#sle-19733)
- usb: roles: Call try_module_get() from ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150400.24.147.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150400.24.147.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150400.24.147.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150400.24.147.1.150400.24.72.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150400.24.147.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150400.24.147.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150400.24.147.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150400.24.147.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150400.24.147.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150400.24.147.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150400.24.147.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150400.24.147.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150400.24.147.1", rls:"SLES15.0SP4"))) {
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
