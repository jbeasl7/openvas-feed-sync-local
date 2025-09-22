# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2081.2");
  script_cve_id("CVE-2018-11806", "CVE-2018-12891", "CVE-2018-12892", "CVE-2018-12893", "CVE-2018-3665");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-04 19:06:14 +0000 (Tue, 04 Sep 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2081-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2081-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182081-2.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087289");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1095242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096224");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097521");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097522");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097523");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-October/004736.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2018:2081-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

Security issues fixed:

- CVE-2018-12891: Fix preemption checks bypass in x86 PV MM handling (XSA-264) (bsc#1097521).
- CVE-2018-12892: Fix libxl failure to honour readonly flag on HVM emulated SCSI disks (XSA-266) (bsc#1097523).
- CVE-2018-12893: Fix #DB exception safety check that could be triggered by a guest (XSA-265) (bsc#1097522).
- CVE-2018-11806: Fix heap buffer overflow while reassembling fragmented datagrams (bsc#1096224).
- CVE-2018-3665: Fix lazy FP Save/Restore (XSA-267) (bsc#1095242).

Bug fixes:

- bsc#1027519: Update to Xen 4.7.6 bug fix only release.
- bsc#1087289: Xen BUG at sched_credit.c:1663.
- bsc#1094725: `virsh blockresize` does not work with Xen qdisks.");

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

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.7.6_02~43.36.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.7.6_02~43.36.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.7.6_02~43.36.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.7.6_02~43.36.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.7.6_02~43.36.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.7.6_02~43.36.1", rls:"SLES12.0SP2"))) {
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
