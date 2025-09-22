# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.4300.1");
  script_cve_id("CVE-2018-15468", "CVE-2018-15469", "CVE-2018-15470", "CVE-2018-18883", "CVE-2018-19961", "CVE-2018-19962", "CVE-2018-19965", "CVE-2018-19966", "CVE-2018-3646");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:32 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-28 17:46:22 +0000 (Fri, 28 Dec 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:4300-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:4300-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20184300-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2018:4300-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

Update to Xen 4.10.2 bug fix release (bsc#1027519).

Security vulnerabilities fixed:
CVE-2018-19961, CVE-2018-19962: Fixed an issue related to insufficient
 TLB flushing with AMD IOMMUs, which potentially allowed a guest to
 escalate its privileges, may cause a Denial of Service (DoS) affecting
 the entire host, or may be able to access data it is not supposed to
 access. (XSA-275) (bsc#1115040)

CVE-2018-19965: Fixed an issue related to the INVPCID instruction in
 case non-canonical addresses are accessed, which may allow a guest to
 cause Xen to crash, resulting in a Denial of Service (DoS) affecting the
 entire host. (XSA-279) (bsc#1115045)

CVE-2018-19966: Fixed an issue related to a previous fix for XSA-240,
 which conflicted with shadow paging and allowed a guest to cause Xen to
 crash, resulting in a Denial of Service (DoS). (XSA-280) (bsc#1115047)

CVE-2018-18883: Fixed an issue related to inproper restriction of nested
 VT-x, which allowed a guest to cause Xen to crash, resulting in a Denial
 of Service (DoS). (XSA-278) (bsc#1114405)

CVE-2018-15468: Fixed incorrect MSR_DEBUGCTL handling, which allowed
 guests to enable Branch Trace Store and may cause a Denial of Service
 (DoS) of the entire host. (XSA-269) (bsc#1103276)

CVE-2018-15469: Fixed use of v2 grant tables on ARM, which were not
 properly implemented and may cause a Denial of Service (DoS). (XSA-268)
 (bsc#1103275)

CVE-2018-15470: Fixed an issue in the logic in oxenstored for handling
 writes, which allowed a guest to write memory unbounded leading to
 system-wide Denial
 of Service (DoS). (XSA-272) (bsc#1103279)

CVE-2018-3646: Mitigations for VMM aspects of L1 Terminal Fault
 (XSA-273) (bsc#1091107)

Other bugs fixed:
Fixed an issue related to a domU hang on SLE12-SP3 HV (bsc#1108940)

Fixed an issue with xpti=no-dom0 not working as expected (bsc#1105528)

Fixed a kernel oops related to fs/dcache.c called by
 d_materialise_unique() (bsc#1094508)");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Server Applications 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.10.2_04~3.9.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.10.2_04~3.9.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.10.2_04~3.9.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.10.2_04~3.9.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.10.2_04~3.9.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.10.2_04~3.9.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.10.2_04~3.9.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.10.2_04~3.9.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.10.2_04~3.9.1", rls:"SLES15.0"))) {
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
