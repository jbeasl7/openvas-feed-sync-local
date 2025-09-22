# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2502.1");
  script_cve_id("CVE-2019-16746", "CVE-2020-11668", "CVE-2020-14331", "CVE-2020-1749");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-24 13:13:18 +0000 (Tue, 24 Sep 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2502-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2502-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202502-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173659");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174247");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-September/007360.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel (Live Patch 34 for SLE 12 SP3)' package(s) announced via the SUSE-SU-2020:2502-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 4.4.180-94_127 fixes several issues.

The following security issues were fixed:

- CVE-2020-14331: Fixed a buffer over-write in vgacon_scroll (bsc#1174247).
- CVE-2019-16746: Fixed a buffer overflow in net/wireless/nl80211.c (bsc#1173659).
- CVE-2020-11668: Fixed a memory corruption issue in the Xirlink camera USB driver (bsc#1173942).
- CVE-2020-1749: Fixed a flaw in IPsec where some IPv6 protocols were not encrypted (bsc#1165631).");

  script_tag(name:"affected", value:"'Linux Kernel (Live Patch 34 for SLE 12 SP3)' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_135-default", rpm:"kgraft-patch-4_4_121-92_135-default~2~2.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_138-default", rpm:"kgraft-patch-4_4_121-92_138-default~2~2.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_121-default", rpm:"kgraft-patch-4_4_180-94_121-default~2~2.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_124-default", rpm:"kgraft-patch-4_4_180-94_124-default~2~2.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_127-default", rpm:"kgraft-patch-4_4_180-94_127-default~2~2.2", rls:"SLES12.0SP3"))) {
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
