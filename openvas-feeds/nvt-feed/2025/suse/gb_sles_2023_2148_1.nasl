# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2148.1");
  script_cve_id("CVE-2020-36691", "CVE-2022-2196", "CVE-2022-43945", "CVE-2023-1611", "CVE-2023-1670", "CVE-2023-1838", "CVE-2023-1855", "CVE-2023-1872", "CVE-2023-1989", "CVE-2023-1990", "CVE-2023-1998", "CVE-2023-2008", "CVE-2023-2124", "CVE-2023-2162", "CVE-2023-2176", "CVE-2023-30772");
  script_tag(name:"creation_date", value:"2025-02-17 04:07:12 +0000 (Mon, 17 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-13 14:12:08 +0000 (Fri, 13 Jan 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2148-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2148-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232148-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209687");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209777");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210203");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210301");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210329");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210414");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210453");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210469");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210498");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210506");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210647");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2023-May/029300.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:2148-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2023-2124: Fixed an out of bound access in the XFS subsystem that could have lead to denial-of-service or potentially privilege escalation (bsc#1210498).
- CVE-2023-1872:Fixed a use after free vulnerability in the io_uring subsystem, which could lead to local privilege escalation (bsc#1210414).
- CVE-2022-2196: Fixed a regression related to KVM that allowed for speculative execution attacks (bsc#1206992).
- CVE-2023-1670: Fixed a use after free in the Xircom 16-bit PCMCIA Ethernet driver. A local user could use this flaw to crash the system or potentially escalate their privileges on the system (bsc#1209871).
- CVE-2023-2162: Fixed an use-after-free flaw in iscsi_sw_tcp_session_create (bsc#1210647).
- CVE-2023-2176: A vulnerability was found in compare_netdev_and_ip in drivers/infiniband/core/cma.c in RDMA. The improper cleanup results in out-of-boundary read, where a local user can utilize this problem to crash the system or escalation of privilege (bsc#1210629).
- CVE-2023-1998: Fixed a use after free during login when accessing the shost ipaddress (bsc#1210506).
- CVE-2023-30772: Fixed a race condition and resultant use-after-free in da9150_charger_remove (bsc#1210329).
- CVE-2023-2008: A flaw was found in the fault handler of the udmabuf device driver. An attacker can leverage this vulnerability to escalate privileges and execute arbitrary code (bsc#1210453).
- CVE-2023-1855: Fixed a use after free in xgene_hwmon_remove (bsc#1210202).
- CVE-2020-36691: Fixed a denial of service vulnerability via a nested Netlink policy with a back reference (bsc#1209777).
- CVE-2023-1990: Fixed a use after free in ndlc_remove (bsc#1210337).
- CVE-2023-1989: Fixed a use after free in btsdio_remove (bsc#1210336).
- CVE-2022-43945: Fixed a buffer overflow in the NFSD implementation (bsc#1205128).
- CVE-2023-1611: Fixed an use-after-free flaw in btrfs_search_slot (bsc#1209687).
- CVE-2023-1838: Fixed an use-after-free flaw in virtio network subcomponent. This flaw could allow a local attacker to crash the system and lead to a kernel information leak problem. (bsc#1210203).

The following non-security bugs were fixed:

- Drivers: vmbus: Check for channel allocation before looking up relids (git-fixes).
- cifs: fix negotiate context parsing (bsc#1210301).
- keys: Fix linking a duplicate key to a keyring's assoc_array (bsc#1207088).
- vmxnet3: use gro callback when UPT is enabled (bsc#1209739).");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.3.18~150300.59.121.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.3.18~150300.59.121.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150300.59.121.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150300.59.121.2.150300.18.70.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150300.59.121.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150300.59.121.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150300.59.121.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150300.59.121.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150300.59.121.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150300.59.121.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150300.59.121.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150300.59.121.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150300.59.121.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.3.18~150300.59.121.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150300.59.121.2", rls:"SLES15.0SP3"))) {
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
