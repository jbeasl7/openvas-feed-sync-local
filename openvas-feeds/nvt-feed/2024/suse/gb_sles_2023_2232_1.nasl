# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2232.1");
  script_cve_id("CVE-2017-5753", "CVE-2020-36691", "CVE-2021-3923", "CVE-2021-4203", "CVE-2022-20567", "CVE-2022-43945", "CVE-2023-0394", "CVE-2023-0590", "CVE-2023-0597", "CVE-2023-1076", "CVE-2023-1095", "CVE-2023-1118", "CVE-2023-1390", "CVE-2023-1513", "CVE-2023-1611", "CVE-2023-1670", "CVE-2023-1855", "CVE-2023-1989", "CVE-2023-1990", "CVE-2023-1998", "CVE-2023-2124", "CVE-2023-2162", "CVE-2023-23454", "CVE-2023-23455", "CVE-2023-2483", "CVE-2023-28328", "CVE-2023-28464", "CVE-2023-28772", "CVE-2023-30772");
  script_tag(name:"creation_date", value:"2024-05-07 13:39:54 +0000 (Tue, 07 May 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-07 00:57:52 +0000 (Fri, 07 Apr 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2232-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2232-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232232-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207168");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207795");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208599");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208777");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209008");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209052");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209289");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209291");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209532");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209547");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209549");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209613");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209687");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209777");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209778");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209887");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210124");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210301");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210329");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210469");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210498");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210506");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211037");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2023-May/029439.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:2232-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP4 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2023-2483: Fixed a use after free bug in emac_remove due caused by a race condition (bsc#1211037).
- CVE-2023-2124: Fixed an out of bound access in the XFS subsystem that could have lead to denial-of-service or potentially privilege escalation (bsc#1210498).
- CVE-2023-1670: Fixed a use after free in the Xircom 16-bit PCMCIA Ethernet driver. A local user could use this flaw to crash the system or potentially escalate their privileges on the system (bsc#1209871).
- CVE-2017-5753: Fixed spectre V1 vulnerability on netlink (bsc#1209547).
- CVE-2017-5753: Fixed spectre vulnerability in prlimit (bsc#1209256).
- CVE-2020-36691: Fixed a denial of service (unbounded recursion) vulnerability via a nested Netlink policy with a back reference (bsc#1209613 bsc#1209777).
- CVE-2023-0394: Fixed a null pointer dereference flaw in the network subcomponent in the Linux kernel which could lead to system crash (bsc#1207168).
- CVE-2021-3923: Fixed stack information leak vulnerability that could lead to kernel protection bypass in infiniband RDMA (bsc#1209778).
- CVE-2021-4203: Fixed use-after-free read flaw that was found in sock_getsockopt() in net/core/sock.c due to SO_PEERCRED and SO_PEERGROUPS race with listen() (bsc#1194535).
- CVE-2022-20567: Fixed use after free that could lead to a local privilege escalation in pppol2tp_create of l2tp_ppp.c (bsc#1208850).
- CVE-2022-43945: Fixed a buffer overflow in the NFSD implementation (bsc#1205128).
- CVE-2023-0590: Fixed race condition in qdisc_graft() (bsc#1207795).
- CVE-2023-0597: Fixed lack of randomization of per-cpu entry area in x86/mm (bsc#1207845).
- CVE-2023-1076: Fixed incorrect UID assigned to tun/tap sockets (bsc#1208599).
- CVE-2023-1095: Fixed a NULL pointer dereference in nf_tables due to zeroed list head (bsc#1208777).
- CVE-2023-1118: Fixed a use-after-free bugs caused by ene_tx_irqsim() in media/rc (bsc#1208837).
- CVE-2023-1390: Fixed remote DoS vulnerability in tipc_link_xmit() (bsc#1209289).
- CVE-2023-1513: Fixed an uninitialized portions of the kvm_debugregs structure that could be copied to userspace, causing an information leak (bsc#1209532).
- CVE-2023-1611: Fixed an use-after-free flaw in btrfs_search_slot (bsc#1209687).
- CVE-2023-1855: Fixed an use-after-free flaw in xgene_hwmon_remove (bsc#1210202).
- CVE-2023-1989: Fixed an use-after-free flaw in btsdio_remove (bsc#1210336).
- CVE-2023-1990: Fixed an use-after-free flaw in ndlc_remove (bsc#1210337).
- CVE-2023-1998: Fixed an use-after-free flaw during login when accessing the shost ipaddress (bsc#1210506).
- CVE-2023-2162: Fixed an use-after-free flaw in iscsi_sw_tcp_session_create (bsc#1210647).
- CVE-2023-23454: Fixed a type-confusion in the CBQ network scheduler (bsc#1207036).
- CVE-2023-23455: Fixed a denial of ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~95.125.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~95.125.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~95.125.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~95.125.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~95.125.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~95.125.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~95.125.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~95.125.1", rls:"SLES12.0SP4"))) {
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
