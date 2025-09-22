# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.3390.1");
  script_cve_id("CVE-2022-40982", "CVE-2023-0459", "CVE-2023-20569", "CVE-2023-20593", "CVE-2023-2985", "CVE-2023-3117", "CVE-2023-3390", "CVE-2023-34319", "CVE-2023-35001", "CVE-2023-3567", "CVE-2023-3609", "CVE-2023-3611", "CVE-2023-3776", "CVE-2023-3812", "CVE-2023-4133", "CVE-2023-4194");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-02 15:09:10 +0000 (Wed, 02 Aug 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:3390-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3390-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20233390-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206418");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209342");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211867");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212301");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212741");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212835");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213059");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213167");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213245");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213287");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213543");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213546");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213586");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213588");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213868");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213970");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214019");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-August/015998.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:3390-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2022-40982: Fixed transient execution attack called 'Gather Data Sampling' (bsc#1206418).
- CVE-2023-0459: Fixed information leak in __uaccess_begin_nospec (bsc#1211738).
- CVE-2023-20569: Fixed side channel attack 'Inception' or 'RAS Poisoning' (bsc#1213287).
- CVE-2023-20593: Fixed a ZenBleed issue in 'Zen 2' CPUs that could allow an attacker to potentially access sensitive information (bsc#1213286).
- CVE-2023-2985: Fixed an use-after-free vulnerability in hfsplus_put_super in fs/hfsplus/super.c that could allow a local user to cause a denial of service (bsc#1211867).
- CVE-2023-3117: Fixed an use-after-free vulnerability in the netfilter subsystem when processing named and anonymous sets in batch requests that could allow a local user with CAP_NET_ADMIN capability to crash or potentially escalate their privileges on the system (bsc#1213245).
- CVE-2023-3390: Fixed an use-after-free vulnerability in the netfilter subsystem in net/netfilter/nf_tables_api.c that could allow a local attacker with user access to cause a privilege escalation issue (bsc#1212846).
- CVE-2023-34319: Fixed buffer overrun triggered by unusual packet in xen/netback (XSA-432) (bsc#1213546).
- CVE-2023-35001: Fixed an out-of-bounds memory access flaw in nft_byteorder that could allow a local attacker to escalate their privilege (bsc#1213059).
- CVE-2023-3567: Fixed a use-after-free in vcs_read in drivers/tty/vt/vc_screen.c (bsc#1213167).
- CVE-2023-3609: Fixed reference counter leak leading to overflow in net/sched (bsc#1213586).
- CVE-2023-3611: Fixed an out-of-bounds write in net/sched sch_qfq(bsc#1213585).
- CVE-2023-3776: Fixed improper refcount update in cls_fw leads to use-after-free (bsc#1213588).
- CVE-2023-3812: Fixed an out-of-bounds memory access flaw in the TUN/TAP device driver functionality that could allow a local user to crash or potentially escalate their privileges on the system (bsc#1213543).
- CVE-2023-4133: Fixed use after free bugs caused by circular dependency problem in cxgb4 (bsc#1213970).
- CVE-2023-4194: Fixed a type confusion in net tun_chr_open() bsc#1214019).

The following non-security bugs were fixed:

- arm: cpu: switch to arch_cpu_finalize_init() (bsc#1206418).
- arm: spear: do not use timer namespace for timer_shutdown() function (bsc#1213970).
- fix kabi when adding new cpuid leaves
- get module prefix from kmod (bsc#1212835).
- remove more packaging cruft for sle &lt, 12 sp3
- cifs: fix open leaks in open_cached_dir() (bsc#1209342).
- clocksource/drivers/arm_arch_timer: do not use timer namespace for timer_shutdown() function (bsc#1213970).
- clocksource/drivers/sp804: do not use timer namespace for timer_shutdown() function (bsc#1213970).
- init, x86: move mem_encrypt_init() into arch_cpu_finalize_init() ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150200.24.160.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150200.24.160.2.150200.9.79.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150200.24.160.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150200.24.160.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150200.24.160.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150200.24.160.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150200.24.160.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150200.24.160.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150200.24.160.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150200.24.160.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150200.24.160.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150200.24.160.2", rls:"SLES15.0SP2"))) {
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
