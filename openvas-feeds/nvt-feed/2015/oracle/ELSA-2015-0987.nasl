# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123122");
  script_cve_id("CVE-2015-3331");
  script_tag(name:"creation_date", value:"2015-10-06 10:59:37 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2015-0987)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-0987");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-0987.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2015-0987 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.10.0-229.4.2]
- Oracle Linux certificates (Alexey Petrenko)

[3.10.0-229.4.2]
- [x86] crypto: aesni - fix memory usage in GCM decryption (Kurt Stutsman) [1213331 1212178] {CVE-2015-3331}

[3.10.0-229.4.1]
- [crypto] x86: sha256_ssse3 - also test for BMI2 (Herbert Xu) [1211484 1201563]
- [crypto] testmgr: fix RNG return code enforcement (Herbert Xu) [1211487 1198978]
- [crypto] rng: RNGs must return 0 in success case (Herbert Xu) [1211487 1198978]
- [crypto] x86: sha1 - reduce size of the AVX2 asm implementation (Herbert Xu) [1211291 1177968]
- [crypto] x86: sha1 - fix stack alignment of AVX2 variant (Herbert Xu) [1211291 1177968]
- [crypto] x86: sha1 - re-enable the AVX variant (Herbert Xu) [1211291 1177968]
- [crypto] sha: SHA1 transform x86_64 AVX2 (Herbert Xu) [1211291 1177968]
- [crypto] sha-mb: sha1_mb_alg_state can be static (Herbert Xu) [1211290 1173756]
- [crypto] mcryptd: mcryptd_flist can be static (Herbert Xu) [1211290 1173756]
- [crypto] sha-mb: SHA1 multibuffer job manager and glue code (Herbert Xu) [1211290 1173756]
- [crypto] sha-mb: SHA1 multibuffer crypto computation (x8 AVX2) (Herbert Xu) [1211290 1173756]
- [crypto] sha-mb: SHA1 multibuffer submit and flush routines for AVX2 (Herbert Xu) [1211290 1173756]
- [crypto] sha-mb: SHA1 multibuffer algorithm data structures (Herbert Xu) [1211290 1173756]
- [crypto] sha-mb: multibuffer crypto infrastructure (Herbert Xu) [1211290 1173756]
- [kernel] sched: Add function single_task_running to let a task check if it is the only task running on a cpu (Herbert Xu) [1211290 1173756]
- [crypto] ahash: initialize entry len for null input in crypto hash sg list walk (Herbert Xu) [1211290 1173756]
- [crypto] ahash: Add real ahash walk interface (Herbert Xu) [1211290 1173756]
- [char] random: account for entropy loss due to overwrites (Herbert Xu) [1211288 1110044]
- [char] random: allow fractional bits to be tracked (Herbert Xu) [1211288 1110044]
- [char] random: statically compute poolbitshift, poolbytes, poolbits (Herbert Xu) [1211288 1110044]

[3.10.0-229.3.1]
- [netdrv] mlx4_en: tx_info->ts_requested was not cleared (Doug Ledford) [1209240 1178070]

[3.10.0-229.2.1]
- [char] tpm: Added Little Endian support to vtpm module (Steve Best) [1207051 1189017]
- [powerpc] pseries: Fix endian problems with LE migration (Steve Best) [1207050 1183198]
- [iommu] vt-d: Work around broken RMRR firmware entries (Myron Stowe) [1205303 1195802]
- [iommu] vt-d: Store bus information in RMRR PCI device path (Myron Stowe) [1205303 1195802]
- [s390] zcrypt: enable s390 hwrng to seed kernel entropy (Hendrik Brueckner) [1205300 1196398]
- [s390] zcrypt: improve device probing for zcrypt adapter cards (Hendrik Brueckner) [1205300 1196398]
- [net] team: fix possible null pointer dereference in team_handle_frame (Jiri Pirko) [1202359 1188496]
- [fs] fsnotify: fix handling of renames in audit (Paul Moore) [1202358 1191562]
- [net] ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~229.4.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~229.4.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~229.4.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~229.4.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~229.4.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~229.4.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~229.4.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~229.4.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~229.4.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~229.4.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~229.4.2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~229.4.2.el7", rls:"OracleLinux7"))) {
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
