# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.14578.1");
  script_cve_id("CVE-2020-29130", "CVE-2020-29480", "CVE-2020-29481", "CVE-2020-29483", "CVE-2020-29484", "CVE-2020-29566", "CVE-2020-29570", "CVE-2020-29571");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:47 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-18 17:29:06 +0000 (Fri, 18 Dec 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:14578-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:14578-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-202014578-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179477");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179496");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179498");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179501");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179502");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179506");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179516");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-December/008079.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2020:14578-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

- CVE-2020-29480: Fixed an issue which could have allowed leak of non-sensitive data to administrator guests (bsc#117949 XSA-115).
- CVE-2020-29481: Fixed an issue which could have allowd to new domains to inherit existing node permissions (bsc#1179498 XSA-322).
- CVE-2020-29483: Fixed an issue where guests could disturb domain cleanup (bsc#1179502 XSA-325).
- CVE-2020-29484: Fixed an issue where guests could crash xenstored via watchs (bsc#1179501 XSA-324).
- CVE-2020-29566: Fixed an undue recursion in x86 HVM context switch code (bsc#1179506 XSA-348).
- CVE-2020-29570: Fixed an issue where FIFO event channels control block related ordering (bsc#1179514 XSA-358).
- CVE-2020-29571: Fixed an issue where FIFO event channels control structure ordering (bsc#1179516 XSA-359).
- CVE-2020-29130: Fixed an out-of-bounds access while processing ARP packets (bsc#1179477).");

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

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.4.4_48~61.61.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.4.4_48~61.61.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.4.4_48_3.0.101_108.117~61.61.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.4.4_48_3.0.101_108.117~61.61.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.4.4_48~61.61.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.4.4_48~61.61.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.4.4_48~61.61.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.4.4_48~61.61.1", rls:"SLES11.0SP4"))) {
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
