# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2783.1");
  script_cve_id("CVE-2019-12068", "CVE-2019-14378", "CVE-2019-15890", "CVE-2019-17340", "CVE-2019-17341", "CVE-2019-17342", "CVE-2019-17343", "CVE-2019-17344", "CVE-2019-17346", "CVE-2019-17347", "CVE-2019-17348");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-10 16:09:26 +0000 (Thu, 10 Oct 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2783-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2783-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192783-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126141");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126196");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126198");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126201");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143797");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146874");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149813");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-October/006058.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2019:2783-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

- CVE-2019-15890: Fixed a use-after-free in SLiRP networking implementation of QEMU emulator
 which could have led to Denial of Service (bsc#1149813).
- CVE-2019-12068: Fixed an issue in lsi which could lead to an infinite loop and denial of
 service (bsc#1146874).
- CVE-2019-14378: Fixed a heap buffer overflow in SLiRp networking implementation of QEMU
 emulator which could have led to execution of arbitrary code with privileges of the
 QEMU process (bsc#1143797).");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.7.6_06~43.54.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.7.6_06~43.54.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.7.6_06~43.54.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.7.6_06~43.54.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.7.6_06~43.54.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.7.6_06~43.54.2", rls:"SLES12.0SP2"))) {
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
