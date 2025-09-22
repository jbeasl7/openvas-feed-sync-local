# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123106");
  script_cve_id("CVE-2014-8159", "CVE-2014-9419", "CVE-2014-9420", "CVE-2014-9585", "CVE-2015-1805", "CVE-2015-3331");
  script_tag(name:"creation_date", value:"2015-10-06 10:59:26 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2015-1081)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1081");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1081.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2015-1081 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-504.23.4]
- [crypto] drbg: fix maximum value checks on 32 bit systems (Herbert Xu) [1225950 1219907]
- [crypto] drbg: remove configuration of fixed values (Herbert Xu) [1225950 1219907]

[2.6.32-504.23.3]
- [netdrv] bonding: fix locking in enslave failure path (Nikolay Aleksandrov) [1222483 1221856]
- [netdrv] bonding: primary_slave & curr_active_slave are not cleaned on enslave failure (Nikolay Aleksandrov) [1222483 1221856]
- [netdrv] bonding: vlans don't get deleted on enslave failure (Nikolay Aleksandrov) [1222483 1221856]
- [netdrv] bonding: mc addresses don't get deleted on enslave failure (Nikolay Aleksandrov) [1222483 1221856]
- [netdrv] bonding: IFF_BONDING is not stripped on enslave failure (Nikolay Aleksandrov) [1222483 1221856]
- [netdrv] bonding: fix error handling if slave is busy v2 (Nikolay Aleksandrov) [1222483 1221856]

[2.6.32-504.23.2]
- [fs] pipe: fix pipe corruption and iovec overrun on partial copy (Seth Jennings) [1202860 1185166] {CVE-2015-1805}

[2.6.32-504.23.1]
- [x86] crypto: sha256_ssse3 - fix stack corruption with SSSE3 and AVX implementations (Herbert Xu) [1218681 1201490]
- [scsi] storvsc: ring buffer failures may result in I/O freeze (Vitaly Kuznetsov) [1215754 1171676]
- [scsi] storvsc: get rid of overly verbose warning messages (Vitaly Kuznetsov) [1215753 1167967]
- [scsi] storvsc: NULL pointer dereference fix (Vitaly Kuznetsov) [1215753 1167967]
- [netdrv] ixgbe: fix detection of SFP+ capable interfaces (John Greene) [1213664 1150343]
- [x86] crypto: aesni - fix memory usage in GCM decryption (Kurt Stutsman) [1213329 1213330] {CVE-2015-3331}

[2.6.32-504.22.1]
- [kernel] hrtimer: Prevent hrtimer_enqueue_reprogram race (Prarit Bhargava) [1211940 1136958]
- [kernel] hrtimer: Preserve timer state in remove_hrtimer() (Prarit Bhargava) [1211940 1136958]
- [crypto] testmgr: fix RNG return code enforcement (Herbert Xu) [1212695 1208804]
- [net] netfilter: xtables: make use of caller family rather than target family (Florian Westphal) [1212057 1210697]
- [net] dynticks: avoid flow_cache_flush() interrupting every core (Marcelo Leitner) [1210595 1191559]
- [tools] perf: Fix race in build_id_cache__add_s() (Milos Vyletel) [1210593 1204102]
- [infiniband] ipath+qib: fix dma settings (Doug Ledford) [1208621 1171803]
- [fs] dcache: return -ESTALE not -EBUSY on distributed fs race (J. Bruce Fields) [1207815 1061994]
- [net] neigh: Keep neighbour cache entries if number of them is small enough (Jiri Pirko) [1207352 1199856]
- [x86] crypto: sha256_ssse3 - also test for BMI2 (Herbert Xu) [1204736 1201560]
- [scsi] qla2xxx: fix race in handling rport deletion during recovery causes panic (Chad Dupuis) [1203544 1102902]
- [redhat] configs: Enable SSSE3 acceleration by default (Herbert Xu) [1201668 1036216]
- [crypto] sha512: Create module providing optimized SHA512 routines using SSSE3, AVX or AVX2 instructions (Herbert Xu) [1201668 1036216]
- ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~504.23.4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~504.23.4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~504.23.4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~504.23.4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~504.23.4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~504.23.4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~504.23.4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~504.23.4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~504.23.4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~504.23.4.el6", rls:"OracleLinux6"))) {
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
