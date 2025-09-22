# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.3392.1");
  script_cve_id("CVE-2022-40982", "CVE-2023-0459", "CVE-2023-20569", "CVE-2023-20593", "CVE-2023-2985", "CVE-2023-34319", "CVE-2023-35001", "CVE-2023-3567", "CVE-2023-3609", "CVE-2023-3611", "CVE-2023-3776", "CVE-2023-4133", "CVE-2023-4194");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-31 17:26:27 +0000 (Mon, 31 Jul 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:3392-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3392-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20233392-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206418");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211867");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212301");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212741");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212835");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213059");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213167");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213287");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213546");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213586");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213588");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213970");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214019");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-August/015997.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:3392-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP1 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2022-40982: Fixed transient execution attack called 'Gather Data Sampling' (bsc#1206418).
- CVE-2023-0459: Fixed information leak in __uaccess_begin_nospec (bsc#1211738).
- CVE-2023-20569: Fixed side channel attack 'Inception' or 'RAS Poisoning' (bsc#1213287).
- CVE-2023-20593: Fixed a ZenBleed issue in 'Zen 2' CPUs that could allow an attacker to potentially access sensitive information (bsc#1213286).
- CVE-2023-2985: Fixed an use-after-free vulnerability in hfsplus_put_super in fs/hfsplus/super.c that could allow a local user to cause a denial of service (bsc#1211867).
- CVE-2023-34319: Fixed buffer overrun triggered by unusual packet in xen/netback (XSA-432) (bsc#1213546).
- CVE-2023-35001: Fixed an out-of-bounds memory access flaw in nft_byteorder that could allow a local attacker to escalate their privilege (bsc#1213059).
- CVE-2023-3567: Fixed a use-after-free in vcs_read in drivers/tty/vt/vc_screen.c (bsc#1213167).
- CVE-2023-3609: Fixed reference counter leak leading to overflow in net/sched (bsc#1213586).
- CVE-2023-3611: Fixed an out-of-bounds write in net/sched sch_qfq(bsc#1213585).
- CVE-2023-3776: Fixed improper refcount update in cls_fw leads to use-after-free (bsc#1213588).
- CVE-2023-4133: Fixed use after free bugs caused by circular dependency problem in cxgb4 (bsc#1213970).
- CVE-2023-4194: Fixed a type confusion in net tun_chr_open() bsc#1214019).

The following non-security bugs were fixed:

- arm: spear: do not use timer namespace for timer_shutdown() function (bsc#1213970).
- clocksource/drivers/arm_arch_timer: do not use timer namespace for timer_shutdown() function (bsc#1213970).
- clocksource/drivers/sp804: do not use timer namespace for timer_shutdown() function (bsc#1213970).
- cpufeatures: allow adding more cpuid words
- get module prefix from kmod (bsc#1212835).
- kernel-binary.spec.in: remove superfluous %% in supplements fixes: 02b7735e0caf ('rpm/kernel-binary.spec.in: add enhances and supplements tags to in-tree kmps')
- kernel-docs: add buildrequires on python3-base when using python3 the python3 binary is provided by python3-base.
- kernel-docs: use python3 together with python3-sphinx (bsc#1212741).
- keys: change keyring_serialise_link_sem to a mutex (bsc#1207088).
- keys: fix linking a duplicate key to a keyring's assoc_array (bsc#1207088).
- keys: hoist locking out of __key_link_begin() (bsc#1207088).
- net/sched: sch_qfq: refactor parsing of netlink parameters (bsc#1213585).
- net: mana: add support for vlan tagging (bsc#1212301).
- readme.branch: add myself as co-maintainer
- remove more packaging cruft for sle &lt, 12 sp3
- rpm/check-for-config-changes: ignore also pahole_has_* we now also have options like config_pahole_has_lang_exclude.
- rpm/check-for-config-changes: ignore also ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~150100.197.154.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~150100.197.154.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~150100.197.154.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~150100.197.154.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~150100.197.154.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.12.14~150100.197.154.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~150100.197.154.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.12.14~150100.197.154.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~150100.197.154.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~150100.197.154.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~4.12.14~150100.197.154.1", rls:"SLES15.0SP1"))) {
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
