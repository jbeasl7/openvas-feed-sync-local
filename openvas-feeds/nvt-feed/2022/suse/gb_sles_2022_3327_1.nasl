# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3327.1");
  script_cve_id("CVE-2019-13224", "CVE-2019-16163", "CVE-2019-19203", "CVE-2019-19204", "CVE-2019-19246", "CVE-2020-26159");
  script_tag(name:"creation_date", value:"2022-09-22 04:47:16 +0000 (Thu, 22 Sep 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-11 20:45:44 +0000 (Thu, 11 Jul 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3327-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3327-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223327-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142847");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150130");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164550");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164569");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177179");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-September/012320.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'oniguruma' package(s) announced via the SUSE-SU-2022:3327-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for oniguruma fixes the following issues:

- CVE-2019-19246: Fixed an out of bounds access during regular
 expression matching (bsc#1157805).
- CVE-2019-19204: Fixed an out of bounds access when compiling a
 crafted regular expression (bsc#1164569).
- CVE-2019-19203: Fixed an out of bounds access when performing a
 string search (bsc#1164550).
- CVE-2019-16163: Fixed an uncontrolled recursion issue when compiling
 a crafted regular expression, which could lead to denial of service (bsc#1150130).
- CVE-2020-26159: Fixed an off-by-one buffer overflow (bsc#1177179).
- CVE-2019-13224: Fixed a potential use-after-free when handling
 multiple different encodings (bsc#1142847).");

  script_tag(name:"affected", value:"'oniguruma' package(s) on SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP2.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libonig4", rpm:"libonig4~6.7.0~150000.3.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libonig4-debuginfo", rpm:"libonig4-debuginfo~6.7.0~150000.3.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oniguruma-debugsource", rpm:"oniguruma-debugsource~6.7.0~150000.3.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oniguruma-devel", rpm:"oniguruma-devel~6.7.0~150000.3.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libonig4", rpm:"libonig4~6.7.0~150000.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libonig4-debuginfo", rpm:"libonig4-debuginfo~6.7.0~150000.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oniguruma-debugsource", rpm:"oniguruma-debugsource~6.7.0~150000.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oniguruma-devel", rpm:"oniguruma-devel~6.7.0~150000.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libonig4", rpm:"libonig4~6.7.0~150000.3.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oniguruma-devel", rpm:"oniguruma-devel~6.7.0~150000.3.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libonig4", rpm:"libonig4~6.7.0~150000.3.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oniguruma-devel", rpm:"oniguruma-devel~6.7.0~150000.3.3.1", rls:"SLES15.0SP2"))) {
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
