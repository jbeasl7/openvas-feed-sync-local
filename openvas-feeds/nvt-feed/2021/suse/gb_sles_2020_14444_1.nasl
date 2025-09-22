# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.14444.1");
  script_cve_id("CVE-2018-12207", "CVE-2019-11135", "CVE-2019-18420", "CVE-2019-18421", "CVE-2019-18424", "CVE-2019-18425", "CVE-2019-19577", "CVE-2019-19578", "CVE-2019-19579", "CVE-2019-19580", "CVE-2019-19583", "CVE-2020-11740", "CVE-2020-11741", "CVE-2020-11742", "CVE-2020-7211", "CVE-2020-8608");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:57 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-06 18:38:02 +0000 (Wed, 06 Nov 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:14444-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:14444-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-202014444-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152497");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154448");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154458");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154461");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158004");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158005");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161181");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163019");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169392");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174543");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-August/007221.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2020:14444-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

- bsc#1174543 - secure boot related fixes
- bsc#1163019 - CVE-2020-8608: potential OOB access due to unsafe snprintf() usages
- bsc#1169392 - CVE-2020-11742: Bad continuation handling in GNTTABOP_copy
- bsc#1168140 - CVE-2020-11740, CVE-2020-11741: multiple xenoprof issues
- bsc#1161181 - CVE-2020-7211: potential directory traversal using relative paths via tftp server on Windows host
- bsc#1157888 - CVE-2019-19579: Device quarantine for alternate pci assignment methods
- bsc#1158004 - CVE-2019-19583: VMX: VMentry failure with debug exceptions and blocked states
- bsc#1158005 - CVE-2019-19578: Linear pagetable use / entry miscounts
- bsc#1158006 - CVE-2019-19580: Further issues with restartable PV type change operations
- bsc#1158007 - CVE-2019-19577: dynamic height for the IOMMU pagetables
- bsc#1154448 - CVE-2019-18420: VCPUOP_initialise DoS
- bsc#1154456 - CVE-2019-18425: missing descriptor table limit checking in x86 PV emulation
- bsc#1154458 - CVE-2019-18421: Issues with restartable PV type change operations
- bsc#1154461 - CVE-2019-18424: passed through PCI devices may corrupt host memory after deassignment
- bsc#1155945 - CVE-2018-12207: Machine Check Error Avoidance on Page Size Change (aka IFU issue)
- bsc#1152497 - CVE-2019-11135: TSX Asynchronous Abort (TAA) issue");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Server 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.4.4_42~61.52.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.4.4_42~61.52.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.4.4_42_3.0.101_108.114~61.52.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.4.4_42_3.0.101_108.114~61.52.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.4.4_42~61.52.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.4.4_42~61.52.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.4.4_42~61.52.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.4.4_42~61.52.1", rls:"SLES11.0SP4"))) {
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
