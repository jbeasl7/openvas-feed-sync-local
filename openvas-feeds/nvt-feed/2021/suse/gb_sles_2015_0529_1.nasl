# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0529.1");
  script_cve_id("CVE-2014-3673", "CVE-2014-3687", "CVE-2014-7822", "CVE-2014-7841", "CVE-2014-8160", "CVE-2014-8559", "CVE-2014-9419", "CVE-2014-9584");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2014-11-10 14:26:04 +0000 (Mon, 10 Nov 2014)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0529-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0529-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150529-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/799216");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/800255");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/860346");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/875220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/877456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/884407");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/895805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/896484");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/897736");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/898687");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/900270");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/902286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/902346");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/902349");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/903640");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904177");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904899");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/905100");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/905304");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/905329");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/905482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/905783");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/906196");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/907069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/908069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/908322");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/908825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/908904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/910322");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/911326");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912654");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/913059");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/914112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/914126");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/914254");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/914291");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/914294");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/914300");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/914457");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/914464");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/914726");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915188");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915322");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915335");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915425");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915454");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915550");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915660");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916513");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916646");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/917089");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/917128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/918161");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/918255");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-March/001296.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2015:0529-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 kernel was updated to 3.12.38 to receive various security and bugfixes.

This update contains the following feature enablements:
- The remote block device (rbd) and ceph drivers have been enabled and
 are now supported. (FATE#318350)
 These can be used e.g. for accessing the SUSE Enterprise Storage product
 services.

- Support for Intel Select Bay trail CPUs has been added. (FATE#316038)

Following security issues were fixed:
- CVE-2014-9419: The __switch_to function in arch/x86/kernel/process_64.c
 in the Linux kernel through 3.18.1 did not ensure that Thread Local
 Storage (TLS) descriptors were loaded before proceeding with other steps,
 which made it easier for local users to bypass the ASLR protection
 mechanism via a crafted application that reads a TLS base address
 (bnc#911326).

- CVE-2014-7822: A flaw was found in the way the Linux kernels splice()
 system call validated its parameters. On certain file systems, a local,
 unprivileged user could have used this flaw to write past the maximum
 file size, and thus crash the system.

- CVE-2014-8160: The connection tracking module could be bypassed if a specific
 protocol module was not loaded, e.g. allowing SCTP traffic while the firewall
 should have filtered it.

- CVE-2014-9584: The parse_rock_ridge_inode_internal function in
 fs/isofs/rock.c in the Linux kernel before 3.18.2 did not validate a
 length value in the Extensions Reference (ER) System Use Field, which
 allowed local users to obtain sensitive information from kernel memory
 via a crafted iso9660 image (bnc#912654).

The following non-security bugs were fixed:
- audit: Allow login in non-init namespaces (bnc#916107).
- btrfs: avoid unnecessary switch of path locks to blocking mode.
- btrfs: fix directory inconsistency after fsync log replay (bnc#915425).
- btrfs: fix fsync log replay for inodes with a mix of regular refs and
 extrefs (bnc#915425).
- btrfs: fix fsync race leading to ordered extent memory leaks (bnc#917128).
- btrfs: fix fsync when extend references are added to an inode (bnc#915425).
- btrfs: fix missing error handler if submiting re-read bio fails.
- btrfs: fix race between transaction commit and empty block group removal (bnc#915550).
- btrfs: fix scrub race leading to use-after-free (bnc#915456).
- btrfs: fix setup_leaf_for_split() to avoid leaf corruption (bnc#915454).
- btrfs: improve free space cache management and space allocation.
- btrfs: make btrfs_search_forward return with nodes unlocked.
- btrfs: scrub, fix sleep in atomic context (bnc#915456).
- btrfs: unlock nodes earlier when inserting items in a btree.
- drm/i915: On G45 enable cursor plane briefly after enabling the display plane (bnc#918161).
- Fix Module.supported handling for external modules (bnc#905304).
- keys: close race between key lookup and freeing (bnc#912202).
- msi: also reject resource with flags all clear.
- pci: Add ACS ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.12.38~44.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.12.38~44.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.12.38~44.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.12.38~44.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~3.12.38~44.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra-debuginfo", rpm:"kernel-ec2-extra-debuginfo~3.12.38~44.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.38~44.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.38~44.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.38~44.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.38~44.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.38~44.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.38~44.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.38~44.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.38~44.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.38~44.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.38~44.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.38~44.1", rls:"SLES12.0"))) {
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
