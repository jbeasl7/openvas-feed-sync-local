# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123305");
  script_cve_id("CVE-2014-3917");
  script_tag(name:"creation_date", value:"2015-10-06 11:02:02 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2014-1281)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-1281");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-1281.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2014-1281 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.10.0-123.8.1]
- Oracle Linux certificates (Alexey Petrenko)

[3.10.0-123.8.1]
- [scsi] fnic: fix broken FIP discovery by initializing multicast address (Chris Leech) [1119727 1100078]
- [scsi] libfcoe: Make fcoe_sysfs optional / fix fnic NULL exception (Chris Leech) [1119727 1100078]
- [fs] nfs: Don't mark the data cache as invalid if it has been flushed (Scott Mayhew) [1115817 1114054]
- [fs] nfs: Clear NFS_INO_REVAL_PAGECACHE when we update the file size (Scott Mayhew) [1115817 1114054]
- [fs] nfs: Fix cache_validity check in nfs_write_pageup todate() (Scott Mayhew) [1115817 1114054]
- [mm] hugetlb: ensure hugepage access is denied if hugepages are not supported (David Gibson) [1122115 1081671]
- [kernel] hrtimer: Prevent all reprogramming if hang detected (Prarit Bhargava) [1113175 1094732]

[3.10.0-123.7.1]
- [scsi] set DID_TIME_OUT correctly (Ewan Milne) [1122575 1103881]
- [scsi] fix invalid setting of host byte (Ewan Milne) [1122575 1103881]
- [scsi] More USB deadlock fixes (Ewan Milne) [1122575 1103881]
- [scsi] Fix USB deadlock caused by SCSI error handling (Ewan Milne) [1122575 1103881]
- [scsi] Fix command result state propagation (Ewan Milne) [1122575 1103881]
- [scsi] Fix spurious request sense in error handling (Ewan Milne) [1122575 1103881]
- [input] synaptics: fix resolution for manually provided min/max (Benjamin Tissoires) [1122559 1093449]
- [input] synaptics: change min/max quirk table to pnp-id matching (Benjamin Tissoires) [1122559 1093449]
- [input] synaptics: add a matches_pnp_id helper function (Benjamin Tissoires) [1122559 1093449]
- [input] synaptics: T540p - unify with other LEN0034 models (Benjamin Tissoires) [1122559 1093449]
- [input] synaptics: add min/max quirk for the ThinkPad W540 (Benjamin Tissoires) [1122559 1093449]
- [input] synaptics: add min/max quirk for ThinkPad Edge E431 (Benjamin Tissoires) [1122559 1093449]
- [input] synaptics: add min/max quirk for ThinkPad T431s, L440, L540, S1 Yoga and X1 (Benjamin Tissoires) [1122559 1093449]
- [input] synaptics: report INPUT_PROP_TOPBUTTONPAD property (Benjamin Tissoires) [1122559 1093449]
- [input] Add INPUT_PROP_TOPBUTTONPAD device property (Benjamin Tissoires) [1122559 1093449]
- [input] i8042: add firmware_id support (Benjamin Tissoires) [1122559 1093449]
- [input] serio: add firmware_id sysfs attribute (Benjamin Tissoires) [1122559 1093449]
- [input] synaptics: add manual min/max quirk for ThinkPad X240 (Benjamin Tissoires) [1122559 1093449]
- [input] synaptics: add manual min/max quirk (Benjamin Tissoires) [1122559 1093449]
- [input] synaptics: fix incorrect placement of __initconst (Benjamin Tissoires) [1122559 1093449]
- [ethernet] be2net: Fix invocation of be_close() after be_clear() (Ivan Vecera) [1122558 1066644]
- [ethernet] be2net: enable interrupts in EEH resume (Ivan Vecera) [1121712 1076682]
- [ethernet] sfc: PIO:Restrict to 64bit arch and use 64-bit writes (Nikolay ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~123.8.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~123.8.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~123.8.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~123.8.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~123.8.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~123.8.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~123.8.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~123.8.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~123.8.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~123.8.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~123.8.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~123.8.1.el7", rls:"OracleLinux7"))) {
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
