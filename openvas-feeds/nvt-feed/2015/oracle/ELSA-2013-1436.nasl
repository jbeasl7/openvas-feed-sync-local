# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123553");
  script_cve_id("CVE-2013-4162", "CVE-2013-4299");
  script_tag(name:"creation_date", value:"2015-10-06 11:05:27 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2013-1436)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-1436");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-1436.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2013-1436 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-358.23.2]
- [md] dm-snapshot: fix data corruption (Mikulas Patocka) [1004252 1004233] {CVE-2013-4299}

[2.6.32-358.23.1]
- [md] raid1, raid10: use freeze_array in place of raise_barrier in various places (Jes Sorensen) [1003765 997845]
- [scsi] megaraid_sas: megaraid_sas driver init fails in kdump kernel (Nikola Pajkovsky) [1001963 833299]
- [char] ipmi: eliminate long delay in ipmi_si on SGI UV2 (Nikola Pajkovsky) [988228 876778]
- [net] bridge: Add multicast_querier toggle and disable queries by default (Nikola Pajkovsky) [995334 905561]
- [net] bridge: Fix fatal typo in setup of multicast_querier_expired (Nikola Pajkovsky) [995334 905561]
- [net] bridge: Restart queries when last querier expires (Nikola Pajkovsky) [995334 905561]
- [net] bridge: Add br_multicast_start_querier (Flavio Leitner) [995334 905561]
- [kernel] Prevent RT process stall due to missing upstream scheduler bug fix (Larry Woodman) [1006932 1002765]
- [fs] nfs: Minor cleanups for nfs4_handle_exception and nfs4_async_handle_error (Dave Wysochanski) [1006956 998752]
- [firmware] efivars: Use correct efi_pstore_info struct when calling pstore_register (Lenny Szubowicz) [993547 867689]
- [net] bridge: do not call setup_timer() multiple times (Amerigo Wang) [997746 994430]
- [fs] lockd: protect nlm_blocked list (David Jeffery) [993544 967095]
- [net] ipv6: call udp_push_pending_frames when uncorking a socket with AF_INET pending data (Jiri Benc) [987649 987651] {CVE-2013-4162}
- [fs] fuse: readdirplus sanity checks (Niels de Vos) [988708 981741]
- [fs] fuse: readdirplus cleanup (Niels de Vos) [988708 981741]
- [fs] fuse: readdirplus change attributes once (Niels de Vos) [988708 981741]
- [fs] fuse: readdirplus fix instantiate (Niels de Vos) [988708 981741]
- [fs] fuse: fix readdirplus dentry leak (Niels de Vos) [988708 981741]
- [fs] cifs: fix issue mounting of DFS ROOT when redirecting from one domain controller to the next (Sachin Prabhu) [994866 976535]
- [fs] nfs: Make nfs_readdir revalidate less often (Scott Mayhew) [994867 976879]
- [fs] nfs: Make nfs_attribute_cache_expired() non-static (Scott Mayhew) [994867 976879]
- [fs] nfs: set verifier on existing dentries in nfs_prime_dcache (Scott Mayhew) [994867 976879]
- [fs] nfs: Allow nfs_updatepage to extend a write under additional circumstances (Scott Mayhew) [987262 983288]
- [fs] nfs: fix a leak at nfs_lookup_revalidate() (Dave Wysochanski) [987261 975211]
- [acpi] efivars: If pstore_register fails, free unneeded pstore buffer (Lenny Szubowicz) [993547 867689]
- [acpi] Eliminate console msg if pstore.backend excludes ERST (Lenny Szubowicz) [993547 867689]
- [acpi] Return unique error if backend registration excluded by kernel param (Lenny Szubowicz) [993547 867689]
- [net] bridge: fix some kernel warning in multicast timer (Amerigo Wang) [997745 952012]
- [net] bridge: send query as soon as leave is received (Amerigo Wang) [997745 ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~358.23.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~358.23.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~358.23.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~358.23.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~358.23.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~358.23.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~358.23.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~358.23.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~358.23.2.el6", rls:"OracleLinux6"))) {
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
