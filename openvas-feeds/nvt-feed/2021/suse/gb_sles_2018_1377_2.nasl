# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1377.2");
  script_cve_id("CVE-2018-3639");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-14 14:51:06 +0000 (Wed, 14 Apr 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1377-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1377-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181377-2.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080157");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090953");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1091041");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1092289");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1093215");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094019");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-October/004726.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:1377-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP2 LTSS kernel was updated to receive various security and bugfixes.

The following security bug was fixed:

- CVE-2018-3639: Information leaks using 'Memory Disambiguation' feature
 in modern CPUs were mitigated, aka 'Spectre Variant 4' (bnc#1087082).

 A new boot commandline option was introduced,
 'spec_store_bypass_disable', which can have following values:

 - auto: Kernel detects whether your CPU model contains an implementation
 of Speculative Store Bypass and picks the most appropriate mitigation.
 - on: disable Speculative Store Bypass
 - off: enable Speculative Store Bypass
 - prctl: Control Speculative Store Bypass per thread via
 prctl. Speculative Store Bypass is enabled for a process by default. The
 state of the control is inherited on fork.
 - seccomp: Same as 'prctl' above, but all seccomp threads will disable
 SSB unless they explicitly opt out.

 The default is 'seccomp', meaning programs need explicit opt-in into the mitigation.

 Status can be queried via the /sys/devices/system/cpu/vulnerabilities/spec_store_bypass file, containing:

 - 'Vulnerable'
 - 'Mitigation: Speculative Store Bypass disabled'
 - 'Mitigation: Speculative Store Bypass disabled via prctl'
 - 'Mitigation: Speculative Store Bypass disabled via prctl and seccomp'

The following related and non-security bugs were fixed:

- cpuid: Fix cpuid.edx.7.0 propagation to guest
- ext4: Fix hole length detection in ext4_ind_map_blocks() (bsc#1090953).
- ibmvnic: Clean actual number of RX or TX pools (bsc#1092289).
- kvm: Introduce nopvspin kernel parameter (bsc#1056427).
- kvm: Fix nopvspin static branch init usage (bsc#1056427).
- powerpc/64: Use barrier_nospec in syscall entry (bsc#1068032, bsc#1080157).
- powerpc/64s: Add barrier_nospec (bsc#1068032, bsc#1080157).
- powerpc/64s: Add support for ori barrier_nospec patching (bsc#1068032, bsc#1080157).
- powerpc/64s: Enable barrier_nospec based on firmware settings (bsc#1068032, bsc#1080157).
- powerpc/64s: Enhance the information in cpu_show_meltdown() (bsc#1068032, bsc#1075087, bsc#1091041).
- powerpc/64s: Enhance the information in cpu_show_spectre_v1() (bsc#1068032).
- powerpc/64s: Fix section mismatch warnings from setup_rfi_flush() (bsc#1068032, bsc#1075087, bsc#1091041).
- powerpc/64s: Move cpu_show_meltdown() (bsc#1068032, bsc#1075087, bsc#1091041).
- powerpc/64s: Patch barrier_nospec in modules (bsc#1068032, bsc#1080157).
- powerpc/64s: Wire up cpu_show_spectre_v1() (bsc#1068032, bsc#1075087, bsc#1091041).
- powerpc/64s: Wire up cpu_show_spectre_v2() (bsc#1068032, bsc#1075087, bsc#1091041).
- powerpc/powernv: Set or clear security feature flags (bsc#1068032, bsc#1075087, bsc#1091041).
- powerpc/powernv: Use the security flags in pnv_setup_rfi_flush() (bsc#1068032, bsc#1075087, bsc#1091041).
- powerpc/pseries: Add new H_GET_CPU_CHARACTERISTICS flags (bsc#1068032, bsc#1075087, bsc#1091041).
- ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.121~92.80.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.121~92.80.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.121~92.80.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.121~92.80.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.121~92.80.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.121~92.80.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.121~92.80.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_80-default", rpm:"kgraft-patch-4_4_121-92_80-default~1~3.5.2", rls:"SLES12.0SP2"))) {
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
