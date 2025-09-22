# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.4589.1");
  script_cve_id("CVE-2021-4037", "CVE-2022-2153", "CVE-2022-2602", "CVE-2022-28693", "CVE-2022-28748", "CVE-2022-2964", "CVE-2022-2978", "CVE-2022-3169", "CVE-2022-3176", "CVE-2022-3424", "CVE-2022-3521", "CVE-2022-3524", "CVE-2022-3535", "CVE-2022-3542", "CVE-2022-3545", "CVE-2022-3565", "CVE-2022-3567", "CVE-2022-3577", "CVE-2022-3586", "CVE-2022-3594", "CVE-2022-3621", "CVE-2022-3625", "CVE-2022-3628", "CVE-2022-3629", "CVE-2022-3635", "CVE-2022-3646", "CVE-2022-3649", "CVE-2022-3707", "CVE-2022-3903", "CVE-2022-39189", "CVE-2022-40307", "CVE-2022-40768", "CVE-2022-4095", "CVE-2022-4129", "CVE-2022-4139", "CVE-2022-41850", "CVE-2022-41858", "CVE-2022-42703", "CVE-2022-42895", "CVE-2022-42896", "CVE-2022-43750", "CVE-2022-4378", "CVE-2022-43945", "CVE-2022-45934");
  script_tag(name:"creation_date", value:"2022-12-21 04:18:03 +0000 (Wed, 21 Dec 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-28 01:27:19 +0000 (Mon, 28 Nov 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:4589-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:4589-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20224589-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198702");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199365");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201455");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202686");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203008");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203066");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203067");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203290");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203322");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203391");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203496");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203511");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203860");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204017");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204166");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204168");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204228");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204402");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204414");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204415");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204417");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204431");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204432");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204439");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204470");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204479");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204486");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204574");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204636");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204637");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204646");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204868");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205130");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205473");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205711");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206207");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-December/013294.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:4589-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2022-4378: Fixed stack overflow in __do_proc_dointvec (bsc#1206207).
- CVE-2022-3635: Fixed a use-after-free in the tst_timer() of the file drivers/atm/idt77252.c (bsc#1204631).
- CVE-2022-3424: Fixed use-after-free in gru_set_context_option(), gru_fault() and gru_handle_user_call_os() that could lead to kernel panic (bsc#1204166).
- CVE-2022-41850: Fixed a race condition in roccat_report_event() in drivers/hid/hid-roccat.c (bsc#1203960).
- CVE-2022-45934: Fixed a integer wraparound via L2CAP_CONF_REQ packets in l2cap_config_req in net/bluetooth/l2cap_core.c (bsc#1205796).
- CVE-2022-3628: Fixed potential buffer overflow in brcmf_fweh_event_worker() in wifi/brcmfmac (bsc#1204868).
- CVE-2022-3567: Fixed a to race condition in inet6_stream_ops()/inet6_dgram_ops() (bsc#1204414).
- CVE-2022-41858: Fixed a denial of service in sl_tx_timeout() in drivers/net/slip (bsc#1205671).
- CVE-2022-43945: Fixed a buffer overflow in the NFSD implementation (bsc#1205128).
- CVE-2022-4095: Fixed a use-after-free in rtl8712 driver (bsc#1205514).
- CVE-2022-3903: Fixed a denial of service with the Infrared Transceiver USB driver (bsc#1205220).
- CVE-2022-2964: Fixed memory corruption issues in ax88179_178a devices (bsc#1202686).
- CVE-2021-4037: Fixed function logic vulnerability that allowed local users to create files for the XFS file-system with an unintended group ownership and with group execution and SGID permission bits set (bsc#1198702).
- CVE-2022-43750: Fixed vulnerability in usbmon that allowed a user-space client to corrupt the monitor's internal memory (bsc#1204653).
- CVE-2022-3542: Fixed memory leak in bnx2x_tpa_stop() in drivers/net/ethernet/broadcom/bnx2x/bnx2x_cmn.c (bsc#1204402).
- CVE-2022-3629: Fixed memory leak in vsock_connect() in net/vmw_vsock/af_vsock.c (bsc#1204635).
- CVE-2022-3646: Fixed memory leak in nilfs_attach_log_writer() in fs/nilfs2/segment.c (bsc#1204646).
- CVE-2022-3649: Fixed use-after-free in nilfs_new_inode() in fs/nilfs2/inode.c (bsc#1204647).
- CVE-2022-3621: Fixed null pointer dereference in nilfs_bmap_lookup_at_level() in fs/nilfs2/inode.c (bsc#1204574).
- CVE-2022-3594: Fixed excessive data logging in intr_callback() in drivers/net/usb/r8152.c (bsc#1204479).
- CVE-2022-3586: Fixed use-after-free in socket buffer (SKB) that could allow a local unprivileged user to cause a denial of service (bsc#1204439).
- CVE-2022-3565: Fixed use-after-free in del_timer() in drivers/isdn/mISDN/l1oip_core.c (bsc#1204431).
- CVE-2022-3524: Fixed memory leak in ipv6_renew_options() in the IPv6 handler (bsc#1204354).
- CVE-2022-40768: Fixed information leak in the scsi driver which allowed local users to obtain sensitive information from kernel memory (bsc#1203514).
- CVE-2022-42703: Fixed use-after-free in mm/rmap.c ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150200.24.139.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150200.24.139.1.150200.9.65.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150200.24.139.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150200.24.139.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150200.24.139.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150200.24.139.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150200.24.139.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150200.24.139.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150200.24.139.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150200.24.139.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150200.24.139.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150200.24.139.1", rls:"SLES15.0SP2"))) {
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
