# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123190");
  script_cve_id("CVE-2014-7841");
  script_tag(name:"creation_date", value:"2015-10-06 06:49:03 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2015-3004)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux5|OracleLinux6)");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-3004");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-3004.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-uek' package(s) announced via the ELSA-2015-3004 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.39-400.246.2]
- net: sctp: fix NULL pointer dereference in af->from_addr_param on malformed packet (Daniel Borkmann) [Orabug: 20425333] {CVE-2014-7841}

[2.6.39-400.246.1]
- sched: Fix possible divide by zero in avg_atom() calculation (Mateusz Guzik) [Orabug: 20148169]
- include/linux/math64.h: add div64_ul() (Alex Shi)
- deadlock when two nodes are converting same lock from PR to EX and idletimeout closes conn (Tariq Saeed) [Orabug: 18639535]
- bonding: Bond master should reflect slave's features. (Ashish Samant) [Orabug: 20231825]
- x86, fpu: remove the logic of non-eager fpu mem allocation at the first usage (Annie Li) [Orabug: 20239143]
- x86, fpu: remove cpu_has_xmm check in the fx_finit() (Suresh Siddha) [Orabug: 20239143]
- x86, fpu: make eagerfpu= boot param tri-state (Suresh Siddha) [Orabug: 20239143]
- x86, fpu: enable eagerfpu by default for xsaveopt (Suresh Siddha) [Orabug: 20239143]
- x86, fpu: decouple non-lazy/eager fpu restore from xsave (Suresh Siddha) [Orabug: 20239143]
- x86, fpu: use non-lazy fpu restore for processors supporting xsave (Suresh Siddha) [Orabug: 20239143]
- lguest, x86: handle guest TS bit for lazy/non-lazy fpu host models (Suresh Siddha) [Orabug: 20239143]
- x86, fpu: always use kernel_fpu_begin/end() for in-kernel FPU usage (Suresh Siddha) [Orabug: 20239143]
- x86, kvm: use kernel_fpu_begin/end() in kvm_load/put_guest_fpu() (Suresh Siddha) [Orabug: 20239143]
- x86, fpu: remove unnecessary user_fpu_end() in save_xstate_sig() (Suresh Siddha) [Orabug: 20239143]
- raid5: add AVX optimized RAID5 checksumming (Jim Kukunas) [Orabug: 20239143]
- x86, fpu: drop the fpu state during thread exit (Suresh Siddha) [Orabug: 20239143]
- x32: Add a thread flag for x32 processes (H. Peter Anvin) [Orabug: 20239143]
- x86, fpu: Unify signal handling code paths for x86 and x86_64 kernels (Suresh Siddha) [Orabug: 20239143]
- x86, fpu: Consolidate inline asm routines for saving/restoring fpu state (Suresh Siddha) [Orabug: 20239143]
- x86, signal: Cleanup ifdefs and is_ia32, is_x32 (Suresh Siddha) [Orabug: 20239143]
into exported and internal interfaces (Linus Torvalds) [Orabug: 20239143]
- i387: Uninline the generic FP helpers that we expose to kernel modules (Linus Torvalds) [Orabug: 20239143]
- i387: use 'restore_fpu_checking()' directly in task switching code (Linus Torvalds) [Orabug: 20239143]
- i387: fix up some fpu_counter confusion (Linus Torvalds) [Orabug: 20239143]");

  script_tag(name:"affected", value:"'kernel-uek' package(s) on Oracle Linux 5, Oracle Linux 6.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~400.246.2.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~400.246.2.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~400.246.2.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~400.246.2.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~400.246.2.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~400.246.2.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~400.246.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~400.246.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~400.246.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~400.246.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~400.246.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~400.246.2.el6uek", rls:"OracleLinux6"))) {
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
