# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1482.1");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:44 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1482-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1482-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181482-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1072689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088343");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089386");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090607");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1091659");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1092497");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1093600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1093710");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919382");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-May/004105.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:1482-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various security and bugfixes.

This update main focus is a regression fix in SystemV IPC handling. (bsc#1093600)

The following non-security bugs were fixed:

- Drop cBPF SSBD as classic BPF does not really have a proper concept of pointers, and without eBPF maps the out-of-bounds access in speculative execution branch can't be mounted. Moreoever, seccomp BPF uses only such a subset of BPF that can only do absolute indexing, and therefore seccomp data buffer boundarier can't be crossed. Information condensed from Alexei and Kees.
- ibrs used instead of retpoline on Haswell processor with spectre_v2=retpoline (bsc#1092497)
- ib/mlx4: Convert slave port before building address-handle (bug#919382 FATE#317529).
- KABI protect struct _lowcore (bsc#1089386).
- Update config files, add Spectre mitigation for s390x (bnc#1089386, LTC#166572).
- Update s390 config files (bsc#1089386).
- fanotify: fix logic of events on child (bsc#1013018).
- ipc/msg: Fix faulty parsing of msgctl args (bsc#1093600,bsc#1072689).
- ocfs2/dlm: Fix up kABI in dlm_ctxt (bsc#1070404).
- ocfs2/dlm: wait for dlm recovery done when migrating all lock resources (bsc#1013018).
- powerpc, KVM: Split HVMODE_206 cpu feature bit into separate HV and architecture bits (bsc#1087082).
- powerpc: Fix /proc/cpuinfo revision for POWER9 DD2 (FATE#325713, bsc#1093710).
- s390/cio: update chpid descriptor after resource accessibility event (bnc#1091659, LTC#167429).
- s390/dasd: fix IO error for newly defined devices (bnc#1091659, LTC#167398).
- s390/qdio: fix access to uninitialized qdio_q fields (bnc#1091659, LTC#168037).
- s390/qeth: on channel error, reject further cmd requests (bnc#1088343, LTC#165985).
- s390: add automatic detection of the spectre defense (bnc#1089386, LTC#166572).
- s390: add optimized array_index_mask_nospec (bnc#1089386, LTC#166572).
- s390: add sysfs attributes for spectre (bnc#1089386, LTC#166572).
- s390: correct module section names for expoline code revert (bsc#1089386).
- s390: correct nospec auto detection init order (bnc#1089386, LTC#166572).
- s390: do not bypass BPENTER for interrupt system calls (bnc#1089386, LTC#166572).
- s390: fix retpoline build on 31bit (bsc#1089386).
- s390: improve cpu alternative handling for gmb and nobp (bnc#1089386, LTC#166572).
- s390: introduce execute-trampolines for branches (bnc#1089386, LTC#166572).
- s390: move nobp parameter functions to nospec-branch.c (bnc#1089386, LTC#166572).
- s390: report spectre mitigation via syslog (bnc#1089386, LTC#166572).
- s390: run user space and KVM guests with modified branch prediction (bnc#1089386, LTC#166572).
- s390: scrub registers on kernel entry and KVM exit (bnc#1089386, LTC#166572).
- x86, mce: Fix mce_start_timer semantics (bsc#1090607).
- x86/kaiser: symbol kaiser_set_shadow_pgd() exported with non GPL");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.0.101~108.52.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~3.0.101~108.52.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-extra", rpm:"kernel-ppc64-extra~3.0.101~108.52.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~3.0.101~108.52.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~3.0.101~108.52.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem", rpm:"kernel-bigmem~3.0.101~108.52.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-base", rpm:"kernel-bigmem-base~3.0.101~108.52.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-devel", rpm:"kernel-bigmem-devel~3.0.101~108.52.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~108.52.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~108.52.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~108.52.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~108.52.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~108.52.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~108.52.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~108.52.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~108.52.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~108.52.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~108.52.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~108.52.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~108.52.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~108.52.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~108.52.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~108.52.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~108.52.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~108.52.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~108.52.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~108.52.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~108.52.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~108.52.1", rls:"SLES11.0SP4"))) {
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
