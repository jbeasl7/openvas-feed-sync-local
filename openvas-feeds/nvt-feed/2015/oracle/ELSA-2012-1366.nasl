# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123798");
  script_cve_id("CVE-2012-3412");
  script_tag(name:"creation_date", value:"2015-10-06 11:08:42 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2012-1366)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-1366");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-1366.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2012-1366 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-279.11.1.el6]
- [net] core: Fix napi_gro_frags vs netpoll path (Amerigo Wang) [857854 845347]
- [netdrv] benet: disable BH in callers of be_process_mcc() (Amerigo Wang) [857854 845347]
- [net] bonding: remove IFF_IN_NETPOLL flag (Amerigo Wang) [857854 845347]
- [mm] fix contig_page_data kABI breakage and related memory corruption (Satoru Moriya) [857012 853007]
- [net] sctp: backport sctp cache ipv6 source after route lookup (Michele Baldessari) [858284 855759]
- [net] sctp: backport support of sctp multi-homing ipv6 source address selection (Michele Baldessari) [858284 855759]
- [net] ipv6: backport RTA_PREFSRC ipv6 source route selection support (Michele Baldessari) [858285 851118]
- [netdrv] sfc: Fix maximum number of TSO segments and minimum TX queue size (Nikolay Aleksandrov) [845556 845557] {CVE-2012-3412}
- [s390] zfcp: No automatic port_rescan on events (Hendrik Brueckner) [856316 855131]
- [fs] xfs: push the AIL from memory reclaim and periodic sync (Dave Chinner) [856686 855139]

[2.6.32-279.10.1.el6]
- [mm] hugetlbfs: close race during teardown of hugetlbfs shared page tables (Rafael Aquini) [857334 856325]
- [mm] hugetlbfs: Correctly detect if page tables have just been shared (Rafael Aquini) [857334 856325]
- [kernel] sched: fix divide by zero at {thread_group,task}_times (Stanislaw Gruszka) [856703 843771]");

  script_tag(name:"affected", value:"'kernel' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~279.11.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~279.11.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~279.11.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~279.11.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~279.11.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~279.11.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~279.11.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~279.11.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~279.11.1.el6", rls:"OracleLinux6"))) {
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
