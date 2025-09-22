# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2163.1");
  script_cve_id("CVE-2020-36691", "CVE-2022-43945", "CVE-2023-1611", "CVE-2023-1670", "CVE-2023-1855", "CVE-2023-1989", "CVE-2023-1990", "CVE-2023-1998", "CVE-2023-2124", "CVE-2023-2162", "CVE-2023-2483", "CVE-2023-30772");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-25 17:34:31 +0000 (Thu, 25 May 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2163-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2163-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232163-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142685");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142926");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174777");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190544");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209342");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209687");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209777");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209887");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209999");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210301");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210329");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210430");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210460");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210466");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210469");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210498");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210506");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210534");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211037");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2023-May/029351.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:2163-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2023-2483: Fixed a use after free bug in emac_remove due caused by a race condition (bsc#1211037).
- CVE-2023-2124: Fixed an out of bound access in the XFS subsystem that could have lead to denial-of-service or potentially privilege escalation (bsc#1210498).
- CVE-2023-1670: Fixed a use after free in the Xircom 16-bit PCMCIA Ethernet driver. A local user could use this flaw to crash the system or potentially escalate their privileges on the system (bsc#1209871).
- CVE-2023-2162: Fixed an use-after-free flaw in iscsi_sw_tcp_session_create (bsc#1210647).
- CVE-2023-1998: Fixed a use after free during login when accessing the shost ipaddress (bsc#1210506).
- CVE-2023-30772: Fixed a race condition and resultant use-after-free in da9150_charger_remove (bsc#1210329).
- CVE-2023-1855: Fixed a use after free in xgene_hwmon_remove (bsc#1210202).
- CVE-2023-1989: Fixed a use after free in btsdio_remove (bsc#1210336).
- CVE-2023-1990: Fixed a use after free in ndlc_remove (bsc#1210337).
- CVE-2022-43945: Fixed a buffer overflow in the NFSD implementation (bsc#1205128).
- CVE-2023-1611: Fixed an use-after-free flaw in btrfs_search_slot (bsc#1209687).
- CVE-2020-36691: Fixed a denial of service vulnerability via a nested Netlink policy with a back reference (bsc#1209777).

The following non-security bugs were fixed:

- ARM: 8702/1: head-common.S: Clear lr before jumping to start_kernel() (git-fixes)
- USB: dwc3: fix runtime pm imbalance on probe errors (git-fixes).
- USB: dwc3: fix runtime pm imbalance on unbind (git-fixes).
- arm64: kaslr: Reserve size of ARM64_MEMSTART_ALIGN in linear region (git-fixes)
- ath10k: Fix error handling in case of CE pipe init failure (git-fixes).
- ath10k: Fix missing frame timestamp for beacon/probe-resp (git-fixes).
- ath10k: Fix the parsing error in service available event (git-fixes).
- ath10k: add missing error return code in ath10k_pci_probe() (git-fixes).
- ath10k: fix control-message timeout (git-fixes).
- ath10k: fix division by zero in send path (git-fixes).
- ath10k: fix memory overwrite of the WoWLAN wakeup packet pattern (git-fixes).
- audit: improve audit queue handling when 'audit=1' on cmdline (bsc#1209969).
- bpf, x86: Fix encoding for lower 8-bit registers in BPF_STX BPF_B (git-fixes).
- bs-upload-kernel: Do not skip post-build-checks
- cachefiles: Drop superfluous readpages aops NULL check (bsc#1210430).
- cachefiles: Fix page leak in cachefiles_read_backing_file while vmscan is active (bsc#1210430).
- cachefiles: Fix race between read_waiter and read_copier involving op->to_do (bsc#1210430).
- cachefiles: Handle readpage error correctly (bsc#1210430).
- cgroup/cpuset: Wake up cpuset_attach_wq tasks in cpuset_cancel_attach() (bsc#1210827).
- cifs: fix negotiate context parsing (bsc#1210301).
- ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.159.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.159.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.159.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.159.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.159.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.159.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.159.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.159.1", rls:"SLES12.0SP5"))) {
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
