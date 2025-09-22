# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0857.1");
  script_cve_id("CVE-2019-25162", "CVE-2020-36777", "CVE-2020-36784", "CVE-2021-46904", "CVE-2021-46905", "CVE-2021-46906", "CVE-2021-46915", "CVE-2021-46924", "CVE-2021-46929", "CVE-2021-46932", "CVE-2021-46934", "CVE-2021-46953", "CVE-2021-46964", "CVE-2021-46966", "CVE-2021-46968", "CVE-2021-46974", "CVE-2021-46989", "CVE-2021-47005", "CVE-2021-47012", "CVE-2021-47013", "CVE-2021-47054", "CVE-2021-47060", "CVE-2021-47061", "CVE-2021-47069", "CVE-2021-47076", "CVE-2021-47078", "CVE-2021-47083", "CVE-2022-20154", "CVE-2022-48627", "CVE-2023-28746", "CVE-2023-35827", "CVE-2023-46343", "CVE-2023-51042", "CVE-2023-52340", "CVE-2023-52429", "CVE-2023-52439", "CVE-2023-52443", "CVE-2023-52445", "CVE-2023-52448", "CVE-2023-52449", "CVE-2023-52451", "CVE-2023-52463", "CVE-2023-52475", "CVE-2023-52478", "CVE-2023-52482", "CVE-2023-52502", "CVE-2023-52530", "CVE-2023-52531", "CVE-2023-52532", "CVE-2023-52569", "CVE-2023-52574", "CVE-2023-52597", "CVE-2023-52605", "CVE-2023-6817", "CVE-2024-0340", "CVE-2024-0607", "CVE-2024-1151", "CVE-2024-23849", "CVE-2024-23851", "CVE-2024-26585", "CVE-2024-26586", "CVE-2024-26589", "CVE-2024-26593", "CVE-2024-26595", "CVE-2024-26602", "CVE-2024-26607", "CVE-2024-26622");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-11 17:36:15 +0000 (Wed, 11 Dec 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0857-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0857-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240857-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200599");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218915");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219127");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219146");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219295");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219835");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219915");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220009");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220187");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220238");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220240");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220241");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220243");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220250");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220253");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220255");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220328");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220344");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220398");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220409");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220416");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220418");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220421");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220436");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220444");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220459");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220469");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220538");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220570");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220572");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220599");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220627");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220641");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220649");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220660");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220736");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220737");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220742");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220826");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220860");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220870");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220917");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220918");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220932");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221039");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221040");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-March/018154.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:0857-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security bugfixes.

The following security bugs were fixed:

- CVE-2023-28746: Fixed Register File Data Sampling (bsc#1213456).
- CVE-2023-52502: Fixed a race condition in nfc_llcp_sock_get() and nfc_llcp_sock_get_sn() (bsc#1220831).
- CVE-2024-26589: Fixed out of bounds read due to variable offset alu on PTR_TO_FLOW_KEYS (bsc#1220255).
- CVE-2024-26585: Fixed race between tx work scheduling and socket close (bsc#1220187).
- CVE-2023-52340: Fixed ICMPv6 'Packet Too Big' packets force a DoS of the Linux kernel by forcing 100% CPU (bsc#1219295).
- CVE-2024-0607: Fixed 64-bit load issue in nft_byteorder_eval() (bsc#1218915).
- CVE-2023-6817: Fixed use-after-free in nft_pipapo_walk (bsc#1218195).
- CVE-2024-26622: Fixed UAF write bug in tomoyo_write_control() (bsc#1220825).
- CVE-2023-52451: Fixed access beyond end of drmem array (bsc#1220250).
- CVE-2021-46932: Fixed missing work initialization before device registration (bsc#1220444)
- CVE-2023-52463: Fixed null pointer dereference in efivarfs (bsc#1220328).
- CVE-2023-52449: Fixed gluebi NULL pointer dereference caused by ftl notifier (bsc#1220238).
- CVE-2023-52475: Fixed use-after-free in powermate_config_complete (bsc#1220649)
- CVE-2023-52478: Fixed kernel crash on receiver USB disconnect (bsc#1220796)
- CVE-2021-46915: Fixed a bug to avoid possible divide error in nft_limit_init (bsc#1220436).
- CVE-2021-46924: Fixed fix memory leak in device probe and remove (bsc#1220459)
- CVE-2019-25162: Fixed a potential use after free (bsc#1220409).
- CVE-2020-36784: Fixed reference leak when pm_runtime_get_sync fails (bsc#1220570).
- CVE-2023-52445: Fixed use after free on context disconnection (bsc#1220241).
- CVE-2023-46343: Fixed a NULL pointer dereference in send_acknowledge() (CVE-2023-46343).
- CVE-2023-52439: Fixed use-after-free in uio_open (bsc#1220140).
- CVE-2023-52443: Fixed crash when parsed profile name is empty (bsc#1220240).
- CVE-2024-26602: Fixed overall slowdowns with sys_membarrier (bsc1220398).
- CVE-2024-26593: Fixed block process call transactions (bsc#1220009).
- CVE-2021-47013: Fixed a use after free in emac_mac_tx_buf_send (bsc#1220641).
- CVE-2024-26586: Fixed stack corruption (bsc#1220243).
- CVE-2024-26595: Fixed NULL pointer dereference in error path (bsc#1220344).
- CVE-2023-52448: Fixed kernel NULL pointer dereference in gfs2_rgrp_dump (bsc#1220253).
- CVE-2024-1151: Fixed unlimited number of recursions from action sets (bsc#1219835).
- CVE-2024-23849: Fixed array-index-out-of-bounds in rds_cmsg_recv (bsc#1219127).
- CVE-2024-0340: Fixed information disclosure in vhost/vhost.c:vhost_new_msg() (bsc#1218689).
- CVE-2023-51042: Fixed use-after-free in amdgpu_cs_wait_all_fences in drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c (bsc#1219128).
- CVE-2021-47078: Fixed a bug by clearing all QP fields if creation failed (bsc#1220863)
- ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.3.18~150300.59.153.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.3.18~150300.59.153.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150300.59.153.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150300.59.153.2.150300.18.90.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150300.59.153.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150300.59.153.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150300.59.153.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150300.59.153.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150300.59.153.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150300.59.153.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150300.59.153.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150300.59.153.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150300.59.153.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.3.18~150300.59.153.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150300.59.153.2", rls:"SLES15.0SP3"))) {
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
