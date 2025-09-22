# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2730.1");
  script_cve_id("CVE-2018-1122", "CVE-2018-1123", "CVE-2018-1124", "CVE-2018-1125", "CVE-2018-1126");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:15 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-22 13:51:14 +0000 (Fri, 22 Jun 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2730-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2730-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192730-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'procps' package(s) announced via the SUSE-SU-2019:2730-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for procps fixes the following issues:

procps was updated to 3.3.15. (bsc#1092100)

Following security issues were fixed:
CVE-2018-1122: Prevent local privilege escalation in top. If a user ran
 top with HOME unset in an attacker-controlled directory, the attacker
 could have achieved privilege escalation by exploiting one of several
 vulnerabilities in the config_file() function (bsc#1092100).

CVE-2018-1123: Prevent denial of service in ps via mmap buffer overflow.
 Inbuilt protection in ps maped a guard page at the end of the overflowed
 buffer, ensuring that the impact of this flaw is limited to a crash
 (temporary denial of service) (bsc#1092100).

CVE-2018-1124: Prevent multiple integer overflows leading to a heap
 corruption in file2strvec function. This allowed a privilege escalation
 for a local attacker who can create entries in procfs by starting
 processes, which could result in crashes or arbitrary code execution in
 proc utilities run by
 other users (bsc#1092100).

CVE-2018-1125: Prevent stack buffer overflow in pgrep. This
 vulnerability was mitigated by FORTIFY limiting the impact to a crash
 (bsc#1092100).

CVE-2018-1126: Ensure correct integer size in proc/alloc.* to prevent
 truncation/integer overflow issues (bsc#1092100).


Also this non-security issue was fixed:
Fix CPU summary showing old data. (bsc#1121753)

The update to 3.3.15 contains the following fixes:
library: Increment to 8:0:1 No removals, no new functions Changes: slab
 and pid structures

library: Just check for SIGLOST and don't delete it

library: Fix integer overflow and LPE in file2strvec CVE-2018-1124

library: Use size_t for alloc functions CVE-2018-1126

library: Increase comm size to 64

pgrep: Fix stack-based buffer overflow CVE-2018-1125

pgrep: Remove >15 warning as comm can be longer

ps: Fix buffer overflow in output buffer, causing DOS CVE-2018-1123

ps: Increase command name selection field to 64

top: Don't use cwd for location of config CVE-2018-1122

update translations

library: build on non-glibc systems

free: fix scaling on 32-bit systems

Revert 'Support running with child namespaces'

library: Increment to 7:0:1 No changes, no removals New fuctions:
 numa_init, numa_max_node, numa_node_of_cpu, numa_uninit,
 xalloc_err_handler

doc: Document I idle state in ps.1 and top.1

free: fix some of the SI multiples

kill: -l space between name parses correctly

library: dont use vm_min_free on non Linux

library: don't strip off wchan prefixes (ps & top)

pgrep: warn about 15+ char name only if -f not used

pgrep/pkill: only match in same namespace by default

pidof: specify separator between pids

pkill: Return 0 only if we can kill process

pmap: fix duplicate output line under '-x' option

ps: avoid eip/esp address truncations

ps: recognizes SCHED_DEADLINE as valid CPU scheduler

ps: display NUMA node under which a thread ran

ps: Add seconds display for ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'procps' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Basesystem 15-SP1.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"libprocps7", rpm:"libprocps7~3.3.15~7.7.26", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprocps7-debuginfo", rpm:"libprocps7-debuginfo~3.3.15~7.7.26", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps", rpm:"procps~3.3.15~7.7.26", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps-debuginfo", rpm:"procps-debuginfo~3.3.15~7.7.26", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps-debugsource", rpm:"procps-debugsource~3.3.15~7.7.26", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps-devel", rpm:"procps-devel~3.3.15~7.7.26", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libprocps7", rpm:"libprocps7~3.3.15~7.7.26", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprocps7-debuginfo", rpm:"libprocps7-debuginfo~3.3.15~7.7.26", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps", rpm:"procps~3.3.15~7.7.26", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps-debuginfo", rpm:"procps-debuginfo~3.3.15~7.7.26", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps-debugsource", rpm:"procps-debugsource~3.3.15~7.7.26", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procps-devel", rpm:"procps-devel~3.3.15~7.7.26", rls:"SLES15.0SP1"))) {
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
