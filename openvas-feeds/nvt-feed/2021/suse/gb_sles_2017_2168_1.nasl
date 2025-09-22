# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2168.1");
  script_cve_id("CVE-2017-1000381", "CVE-2017-11499");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:54 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:49+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:49 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-31 19:24:07 +0000 (Mon, 31 Jul 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2168-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2168-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172168-1/");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V6.md#6");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V6.md#6");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V6.md#6");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V6.md#6");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V6.md#6");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V6.md#6");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V4.md#4");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V4.md#4");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V4.md#4");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V4.md#4");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V4.md#4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs4, nodejs6' package(s) announced via the SUSE-SU-2017:2168-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs4 and nodejs6 fixes the following issues:
Security issues fixed:
- CVE-2017-1000381: The c-ares function ares_parse_naptr_reply() could be
 triggered to read memory
 outside of the given input buffer if the passed in DNS response packet
 was crafted in a particular way. (bsc#1044946)
- CVE-2017-11499: Disable V8 snapshots. The hashseed embedded in the
 snapshot is currently the same for all runs of the binary. This opens
 node up to collision attacks which could result in a Denial
 of Service. We have temporarily disabled snapshots until a more robust
 solution is found. (bsc#1048299)
Non-security fixes:
- GCC 7 compilation fixes for v8 backported and add missing ICU59 headers
 (bsc#1041282)
- New upstream LTS release 6.11.1
 *
[link moved to references]
 .11.1
- New upstream LTS release 6.11.0
 *
[link moved to references]
 .11.0
- New upstream LTS release 6.10.3
 *
[link moved to references]
 .10.3
- New upstream LTS release 6.10.2
 *
[link moved to references]
 .10.2
- New upstream LTS release 6.10.1
 *
[link moved to references]
 .10.1
- New upstream LTS release 6.10.0
 *
[link moved to references]
 .10.0
- New upstream LTS release 4.8.4
 *
[link moved to references]
 .8.4
- New upstream LTS release 4.8.3
 *
[link moved to references]
 .8.3
- New upstream LTS release 4.8.2
 *
[link moved to references]
 .8.2
- New upstream LTS release 4.8.1
 *
[link moved to references]
 .8.1
- New upstream LTS release 4.8.0
 *
[link moved to references]
 .8.0");

  script_tag(name:"affected", value:"'nodejs4, nodejs6' package(s) on SUSE Enterprise Storage 4, SUSE Linux Enterprise Module for Web Scripting 12, SUSE OpenStack Cloud 7.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs-common", rpm:"nodejs-common~1.0~2.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs4", rpm:"nodejs4~4.8.4~15.5.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs4-debuginfo", rpm:"nodejs4-debuginfo~4.8.4~15.5.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs4-debugsource", rpm:"nodejs4-debugsource~4.8.4~15.5.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs4-devel", rpm:"nodejs4-devel~4.8.4~15.5.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs4-docs", rpm:"nodejs4-docs~4.8.4~15.5.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs6", rpm:"nodejs6~6.11.1~11.5.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs6-debuginfo", rpm:"nodejs6-debuginfo~6.11.1~11.5.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs6-debugsource", rpm:"nodejs6-debugsource~6.11.1~11.5.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs6-devel", rpm:"nodejs6-devel~6.11.1~11.5.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs6-docs", rpm:"nodejs6-docs~6.11.1~11.5.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm4", rpm:"npm4~4.8.4~15.5.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm6", rpm:"npm6~6.11.1~11.5.1", rls:"SLES12.0"))) {
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
