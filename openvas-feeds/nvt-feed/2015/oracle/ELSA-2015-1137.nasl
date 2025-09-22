# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123095");
  script_cve_id("CVE-2014-9420", "CVE-2014-9529", "CVE-2014-9584", "CVE-2015-1573", "CVE-2015-1593", "CVE-2015-1805", "CVE-2015-2830");
  script_tag(name:"creation_date", value:"2015-10-06 10:59:18 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Oracle: Security Advisory (ELSA-2015-1137)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1137");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1137.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2015-1137 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.10.0-229.7.2]
- Oracle Linux certificates (Alexey Petrenko)

[3.10.0-229.7.2]
- [fs] pipe: fix pipe corruption and iovec overrun on partial copy (Seth Jennings) [1202861 1198843] {CVE-2015-1805}

[3.10.0-229.7.1]
- [scsi] storvsc: get rid of overly verbose warning messages (Vitaly Kuznetsov) [1215770 1206437]
- [scsi] storvsc: force discovery of LUNs that may have been removed (Vitaly Kuznetsov) [1215770 1206437]
- [scsi] storvsc: in response to a scan event, scan the host (Vitaly Kuznetsov) [1215770 1206437]
- [scsi] storvsc: NULL pointer dereference fix (Vitaly Kuznetsov) [1215770 1206437]
- [virtio] defer config changed notifications (David Gibson) [1220278 1196009]
- [virtio] unify config_changed handling (David Gibson) [1220278 1196009]
- [x86] kernel: Remove a bogus 'ret_from_fork' optimization (Mateusz Guzik) [1209234 1209235] {CVE-2015-2830}
- [kernel] futex: Mention key referencing differences between shared and private futexes (Larry Woodman) [1219169 1205862]
- [kernel] futex: Ensure get_futex_key_refs() always implies a barrier (Larry Woodman) [1219169 1205862]
- [scsi] megaraid_sas: revert: Add release date and update driver version (Tomas Henzl) [1216213 1207175]
- [kernel] module: set nx before marking module MODULE_STATE_COMING (Hendrik Brueckner) [1214788 1196977]
- [kernel] module: Clean up ro/nx after early module load failures (Pratyush Anand) [1214403 1202866]
- [drm] radeon: fix kernel segfault in hwmonitor (Jerome Glisse) [1213467 1187817]
- [fs] btrfs: make xattr replace operations atomic (Eric Sandeen) [1205086 1205873]
- [x86] mm: Linux stack ASLR implementation (Jacob Tanenbaum) [1195684 1195685] {CVE-2015-1593}
- [net] netfilter: nf_tables: fix flush ruleset chain dependencies (Jiri Pirko) [1192880 1192881] {CVE-2015-1573}
- [fs] isofs: Fix unchecked printing of ER records (Mateusz Guzik) [1180482 1180483] {CVE-2014-9584}
- [security] keys: memory corruption or panic during key garbage collection (Jacob Tanenbaum) [1179851 1179852] {CVE-2014-9529}
- [fs] isofs: infinite loop in CE record entries (Jacob Tanenbaum) [1175246 1175248] {CVE-2014-9420}

[3.10.0-229.6.1]
- [net] tcp: abort orphan sockets stalling on zero window probes (Florian Westphal) [1215924 1151756]
- [x86] crypto: aesni - fix memory usage in GCM decryption (Kurt Stutsman) [1213331 1212178] {CVE-2015-3331}

[3.10.0-229.5.1]
- [powerpc] mm: thp: Add tracepoints to track hugepage invalidate (Gustavo Duarte) [1212977 1199016]
- [powerpc] mm: Use read barrier when creating real_pte (Gustavo Duarte) [1212977 1199016]
- [powerpc] mm: thp: Use ACCESS_ONCE when loading pmdp (Gustavo Duarte) [1212977 1199016]
- [powerpc] mm: thp: Invalidate with vpn in loop (Gustavo Duarte) [1212977 1199016]
- [powerpc] mm: thp: Handle combo pages in invalidate (Gustavo Duarte) [1212977 1199016]
- [powerpc] mm: thp: Invalidate old 64K based hash page mapping before insert of 4k pte (Gustavo Duarte) ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~229.7.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~229.7.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~229.7.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~229.7.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~229.7.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~229.7.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~229.7.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~229.7.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~229.7.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~229.7.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~229.7.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~229.7.2.el7", rls:"OracleLinux7"))) {
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
