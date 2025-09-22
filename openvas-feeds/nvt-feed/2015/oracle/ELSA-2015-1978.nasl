# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122728");
  script_cve_id("CVE-2014-8559", "CVE-2015-5156");
  script_tag(name:"creation_date", value:"2015-11-08 11:05:18 +0000 (Sun, 08 Nov 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-13 17:42:00 +0000 (Thu, 13 Aug 2020)");

  script_name("Oracle: Security Advisory (ELSA-2015-1978)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1978");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1978.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2015-1978 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.10.0-229.20.1.OL7]
- Oracle Linux certificates (Alexey Petrenko)

[3.10.0-229.20.1]
- Revert: [crypto] nx - Check for bogus firmware properties (Phillip Lougher) [1247127 1190103]
- Revert: [crypto] nx - Moving NX-AES-CBC to be processed logic (Phillip Lougher) [1247127 1190103]
- Revert: [crypto] nx - Moving NX-AES-CCM to be processed logic and sg_list bounds (Phillip Lougher) [1247127 1190103]
- Revert: [crypto] nx - Moving limit and bound logic in CTR and fix IV vector (Phillip Lougher) [1247127 1190103]
- Revert: [crypto] nx - Moving NX-AES-ECB to be processed logic (Phillip Lougher) [1247127 1190103]
- Revert: [crypto] nx - Moving NX-AES-GCM to be processed logic (Phillip Lougher) [1247127 1190103]
- Revert: [crypto] nx - Moving NX-AES-XCBC to be processed logic (Phillip Lougher) [1247127 1190103]
- Revert: [crypto] nx - Fix SHA concurrence issue and sg limit bounds (Phillip Lougher) [1247127 1190103]
- Revert: [crypto] nx - Fixing the limit number of bytes to be processed (Phillip Lougher) [1247127 1190103]

[3.10.0-229.19.1]
- Revert: [fs] xfs: DIO write completion size updates race (Phillip Lougher) [1258942 1213370]
- Revert: [fs] xfs: direct IO EOF zeroing needs to drain AIO (Phillip Lougher) [1258942 1213370]

[3.10.0-229.18.1]
- [scsi] sd: split sd_init_command (Ewan Milne) [1264141 1109348]
- [scsi] sd: retry discard commands (Ewan Milne) [1264141 1109348]
- [scsi] sd: retry write same commands (Ewan Milne) [1264141 1109348]
- [scsi] sd: don't use scsi_setup_blk_pc_cmnd for discard requests (Ewan Milne) [1264141 1109348]
- [scsi] sd: don't use scsi_setup_blk_pc_cmnd for write same requests (Ewan Milne) [1264141 1109348]
- [scsi] sd: don't use scsi_setup_blk_pc_cmnd for flush requests (Ewan Milne) [1264141 1109348]
- [scsi] set sc_data_direction in common code (Ewan Milne) [1264141 1109348]
- [scsi] restructure command initialization for TYPE_FS requests (Ewan Milne) [1264141 1109348]
- [scsi] move the nr_phys_segments assert into scsi_init_io (Ewan Milne) [1264141 1109348]
- [fs] xfs: remove bitfield based superblock updates (Brian Foster) [1261781 1225075]
- [netdrv] ixgbe: fix X540 Completion timeout (John Greene) [1257633 1173786]
- [lib] radix-tree: handle allocation failure in radix_tree_insert() (Seth Jennings) [1264142 1260613]
- [crypto] nx - Fixing the limit number of bytes to be processed (Herbert Xu) [1247127 1190103]
- [crypto] nx - Fix SHA concurrence issue and sg limit bounds (Herbert Xu) [1247127 1190103]
- [crypto] nx - Moving NX-AES-XCBC to be processed logic (Herbert Xu) [1247127 1190103]
- [crypto] nx - Moving NX-AES-GCM to be processed logic (Herbert Xu) [1247127 1190103]
- [crypto] nx - Moving NX-AES-ECB to be processed logic (Herbert Xu) [1247127 1190103]
- [crypto] nx - Moving limit and bound logic in CTR and fix IV vector (Herbert Xu) [1247127 1190103]
- [crypto] nx - Moving NX-AES-CCM to be processed logic and sg_list bounds ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~229.20.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~229.20.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~229.20.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~229.20.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~229.20.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~229.20.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~229.20.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~229.20.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~229.20.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~229.20.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~229.20.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~229.20.1.el7", rls:"OracleLinux7"))) {
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
