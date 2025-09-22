# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123267");
  script_cve_id("CVE-2014-3611", "CVE-2014-3645", "CVE-2014-3646", "CVE-2014-4653", "CVE-2014-5077");
  script_tag(name:"creation_date", value:"2015-10-06 11:01:30 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-13 19:34:00 +0000 (Thu, 13 Aug 2020)");

  script_name("Oracle: Security Advisory (ELSA-2014-1724)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-1724");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-1724.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2014-1724 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.10.0-123.9.2]
- Oracle Linux certificates (Alexey Petrenko)

[3.10.0-123.9.2]
- [virt] kvm: fix PIT timer race condition (Petr Matousek) [1144879 1144880] {CVE-2014-3611}
- [virt] kvm/vmx: handle invept and invvpid vm exits gracefully (Petr Matousek) [1145449 1116936] [1144828 1144829] {CVE-2014-3645 CVE-2014-3646}

[3.10.0-123.9.1]
- [md] raid6: avoid data corruption during recovery of double-degraded RAID6 (Jes Sorensen) [1143850 1130905]
- [fs] ext4: fix type declaration of ext4_validate_block_bitmap (Lukas Czerner) [1140978 1091055]
- [fs] ext4: error out if verifying the block bitmap fails (Lukas Czerner) [1140978 1091055]
- [powerpc] sched: stop updating inside arch_update_cpu_topology() when nothing to be update (Gustavo Duarte) [1140300 1098372]
- [powerpc] 64bit sendfile is capped at 2GB (Gustavo Duarte) [1139126 1107774]
- [s390] fix restore of invalid floating-point-control (Hendrik Brueckner) [1138733 1121965]
- [kernel] sched/fair: Rework sched_fair time accounting (Rik van Riel) [1134717 1123731]
- [kernel] math64: Add mul_u64_u32_shr() (Rik van Riel) [1134717 1123731]
- [kernel] workqueue: zero cpumask of wq_numa_possible_cpumask on init (Motohiro Kosaki) [1134715 1117184]
- [cpufreq] acpi-cpufreq: skip loading acpi_cpufreq after intel_pstate (Motohiro Kosaki) [1134716 1123250]
- [security] selinux: Increase ebitmap_node size for 64-bit configuration (Paul Moore) [1132076 922752]
- [security] selinux: Reduce overhead of mls_level_isvalid() function call (Paul Moore) [1132076 922752]
- [ethernet] cxgb4: allow large buffer size to have page size (Gustavo Duarte) [1130548 1078977]
- [kernel] sched/autogroup: Fix race with task_groups list (Gustavo Duarte) [1129990 1081406]
- [net] sctp: inherit auth_capable on INIT collisions (Daniel Borkmann) [1124337 1123763] {CVE-2014-5077}
- [sound] alsa/control: Don't access controls outside of protected regions (Radomir Vrbovsky) [1117330 1117331] {CVE-2014-4653}");

  script_tag(name:"affected", value:"'kernel' package(s) on Oracle Linux 7.");

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

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~123.9.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~123.9.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~123.9.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~123.9.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~123.9.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~123.9.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~123.9.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~123.9.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~123.9.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~123.9.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~123.9.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~123.9.2.el7", rls:"OracleLinux7"))) {
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
