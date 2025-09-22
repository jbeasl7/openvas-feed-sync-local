# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.13999.1");
  script_cve_id("CVE-2017-5715");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:28 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-14 14:52:07 +0000 (Wed, 14 Apr 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:13999-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:13999-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-201913999-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1095824");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-March/005270.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'various KMPs' package(s) announced via the SUSE-SU-2019:13999-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update rebuilds missing kernel modules (KMP) to use 'retpolines'
mitigations for Spectre Variant 2 (CVE-2017-5715).

Rebuilt KMP packages:

- cluster-network
- drbd
- gfs2
- iscsitarget
- ocfs2
- ofed
- oracleasm");

  script_tag(name:"affected", value:"'various KMPs' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"iscsitarget", rpm:"iscsitarget~1.4.20~0.43.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iscsitarget-kmp-bigmem", rpm:"iscsitarget-kmp-bigmem~1.4.20_3.0.101_108.87~0.43.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iscsitarget-kmp-default", rpm:"iscsitarget-kmp-default~1.4.20_3.0.101_108.87~0.43.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iscsitarget-kmp-pae", rpm:"iscsitarget-kmp-pae~1.4.20_3.0.101_108.87~0.43.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iscsitarget-kmp-ppc64", rpm:"iscsitarget-kmp-ppc64~1.4.20_3.0.101_108.87~0.43.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iscsitarget-kmp-trace", rpm:"iscsitarget-kmp-trace~1.4.20_3.0.101_108.87~0.43.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iscsitarget-kmp-xen", rpm:"iscsitarget-kmp-xen~1.4.20_3.0.101_108.87~0.43.7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofed", rpm:"ofed~1.5.4.1~22.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofed-doc", rpm:"ofed-doc~1.5.4.1~22.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofed-kmp-bigmem", rpm:"ofed-kmp-bigmem~1.5.4.1_3.0.101_108.87~22.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofed-kmp-default", rpm:"ofed-kmp-default~1.5.4.1_3.0.101_108.87~22.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofed-kmp-pae", rpm:"ofed-kmp-pae~1.5.4.1_3.0.101_108.87~22.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofed-kmp-ppc64", rpm:"ofed-kmp-ppc64~1.5.4.1_3.0.101_108.87~22.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofed-kmp-trace", rpm:"ofed-kmp-trace~1.5.4.1_3.0.101_108.87~22.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.0.5~7.44.2.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-kmp-bigmem", rpm:"oracleasm-kmp-bigmem~2.0.5_3.0.101_108.87~7.44.2.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-kmp-default", rpm:"oracleasm-kmp-default~2.0.5_3.0.101_108.87~7.44.2.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-kmp-pae", rpm:"oracleasm-kmp-pae~2.0.5_3.0.101_108.87~7.44.2.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-kmp-ppc64", rpm:"oracleasm-kmp-ppc64~2.0.5_3.0.101_108.87~7.44.2.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-kmp-trace", rpm:"oracleasm-kmp-trace~2.0.5_3.0.101_108.87~7.44.2.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-kmp-xen", rpm:"oracleasm-kmp-xen~2.0.5_3.0.101_108.87~7.44.2.1", rls:"SLES11.0SP4"))) {
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
