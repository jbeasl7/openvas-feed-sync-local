# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.3322.1");
  script_cve_id("CVE-2021-0089", "CVE-2021-20255", "CVE-2021-28690", "CVE-2021-28692", "CVE-2021-28694", "CVE-2021-28695", "CVE-2021-28696", "CVE-2021-28697", "CVE-2021-28698", "CVE-2021-28701", "CVE-2021-3592", "CVE-2021-3594", "CVE-2021-3595");
  script_tag(name:"creation_date", value:"2021-10-09 02:20:16 +0000 (Sat, 09 Oct 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-15 18:42:28 +0000 (Wed, 15 Sep 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:3322-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:3322-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20213322-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182654");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186433");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186434");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187369");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187376");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189373");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189376");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189632");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189882");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-October/009548.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2021:3322-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

- CVE-2021-28701: Fixed race condition in XENMAPSPACE_grant_table handling (XSA-384) (bsc#1189632).

- CVE-2021-28694,CVE-2021-28695,CVE-2021-28696: Fixed IOMMU page mapping issues on x86 (XSA-378)(bsc#1189373).
- CVE-2021-28697: Fixed grant table v2 status pages that may remain accessible after de-allocation (XSA-379)(bsc#1189376).
- CVE-2021-28698: Fixed long running loops in grant table handling (XSA-380)(bsc#1189378).
- CVE-2021-20255: Fixed eepro100 stack overflow via infinite recursion (bsc#1182654).
- CVE-2021-3592: Fixed invalid pointer initialization may lead to information disclosure (bootp) (bsc#1187369).
- CVE-2021-3594: Fixed invalid pointer initialization may lead to information disclosure (udp) (bsc#1187378).
- CVE-2021-3595: Fixed invalid pointer initialization may lead to information disclosure (tftp) (bsc#1187376).
- CVE-2021-28692: Fixed inappropriate x86 IOMMU timeout detection / handling (XSA-373)(bsc#1186429).
- CVE-2021-0089: Fixed Speculative Code Store Bypass (XSA-375)(bsc#1186433).
- CVE-2021-28690: Fixed x86 TSX Async Abort protections not restored after S3 (XSA-377)(bsc#1186434).

- Prevent superpage allocation in the LAPIC and ACPI_INFO range (bsc#1189882).");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Server 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.7.6_16~43.79.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.7.6_16~43.79.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.7.6_16~43.79.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.7.6_16~43.79.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.7.6_16~43.79.5", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.7.6_16~43.79.5", rls:"SLES12.0SP2"))) {
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
