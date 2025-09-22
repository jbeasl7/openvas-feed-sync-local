# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.1650.1");
  script_cve_id("CVE-2021-46955", "CVE-2021-47041", "CVE-2021-47074", "CVE-2021-47113", "CVE-2021-47131", "CVE-2021-47184", "CVE-2021-47185", "CVE-2021-47194", "CVE-2021-47198", "CVE-2021-47201", "CVE-2021-47203", "CVE-2021-47206", "CVE-2021-47207", "CVE-2021-47212", "CVE-2022-48631", "CVE-2022-48651", "CVE-2022-48654", "CVE-2022-48687", "CVE-2023-2860", "CVE-2023-6270", "CVE-2024-0639", "CVE-2024-0841", "CVE-2024-22099", "CVE-2024-23307", "CVE-2024-26688", "CVE-2024-26689", "CVE-2024-26733", "CVE-2024-26739", "CVE-2024-26744", "CVE-2024-26816", "CVE-2024-26840", "CVE-2024-26852", "CVE-2024-26862", "CVE-2024-26898", "CVE-2024-26903", "CVE-2024-26906", "CVE-2024-27043");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-23 19:13:31 +0000 (Mon, 23 Dec 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:1650-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1650-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241650-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204614");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211592");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218917");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219264");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220513");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220755");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221543");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221545");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222449");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222503");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222559");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222624");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222669");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222792");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222881");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222894");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223057");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223111");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223187");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223475");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223513");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223952");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-May/035272.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:1650-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2024-26840: Fixed a memory leak in cachefiles_add_cache() (bsc#1222976).
- CVE-2021-47113: Abort btrfs rename_exchange if we fail to insert the second ref (bsc#1221543).
- CVE-2021-47131: Fixed a use-after-free after the TLS device goes down and up (bsc#1221545).
- CVE-2024-26852: Fixed net/ipv6 to avoid possible UAF in ip6_route_mpath_notify() (bsc#1223057).
- CVE-2021-46955: Fixed an out-of-bounds read with openvswitch, when fragmenting IPv4 packets (bsc#1220513).
- CVE-2024-26862: Fixed packet annotate data-races around ignore_outgoing (bsc#1223111).
- CVE-2024-0639: Fixed a denial-of-service vulnerability due to a deadlock found in sctp_auto_asconf_init in net/sctp/socket.c (bsc#1218917).
- CVE-2024-27043: Fixed a use-after-free in edia/dvbdev in different places (bsc#1223824).
- CVE-2022-48631: Fixed a bug in ext4, when parsing extents where eh_entries == 0 and eh_depth > 0 (bsc#1223475).
- CVE-2024-23307: Fixed Integer Overflow or Wraparound vulnerability in x86 and ARM md, raid, raid5 modules (bsc#1219169).
- CVE-2022-48651: Fixed an out-of-bound bug in ipvlan caused by unset skb->mac_header (bsc#1223513).
- CVE-2024-26816: Fixed relocations in .notes section when building with CONFIG_XEN_PV=y by ignoring them (bsc#1222624).
- CVE-2024-26906: Disallowed vsyscall page read for copy_from_kernel_nofault() (bsc#1223202).
- CVE-2024-26689: Fixed a use-after-free in encode_cap_msg() (bsc#1222503).
- CVE-2021-47041: Don't set sk_user_data without write_lock (bsc#1220755).
- CVE-2021-47074: Fixed memory leak in nvme_loop_create_ctrl() (bsc#1220854).
- CVE-2024-26744: Fixed null pointer dereference in srpt_service_guid parameter in rdma/srpt (bsc#1222449).

The following non-security bugs were fixed:

- net/tls: Remove the context from the list in tls_device_down (bsc#1221545).
- tls: Fix context leak on tls_device_down (bsc#1221545).");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150200.24.191.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150200.24.191.1.150200.9.97.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150200.24.191.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150200.24.191.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150200.24.191.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150200.24.191.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150200.24.191.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150200.24.191.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150200.24.191.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150200.24.191.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150200.24.191.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150200.24.191.1", rls:"SLES15.0SP2"))) {
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
