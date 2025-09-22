# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2355.1");
  script_cve_id("CVE-2020-14349", "CVE-2020-14350");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:56 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-02 19:05:15 +0000 (Wed, 02 Sep 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2355-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2355-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202355-1/");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/10/release-10-14.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql10' package(s) announced via the SUSE-SU-2020:2355-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql10 fixes the following issues:

update to 10.14:
 * CVE-2020-14349, bsc#1175193: Set a secure search_path in logical
 replication walsenders and apply workers
 * CVE-2020-14350, bsc#1175194: Make contrib modules' installation
 scripts more secure.
 * [link moved to references]");

  script_tag(name:"affected", value:"'postgresql10' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise Module for Server Applications 15-SP1, SUSE Linux Enterprise Module for Server Applications 15-SP2.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"postgresql10", rpm:"postgresql10~10.14~8.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-debuginfo", rpm:"postgresql10-debuginfo~10.14~8.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-debugsource", rpm:"postgresql10-debugsource~10.14~8.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-contrib", rpm:"postgresql10-contrib~10.14~8.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-contrib-debuginfo", rpm:"postgresql10-contrib-debuginfo~10.14~8.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-devel", rpm:"postgresql10-devel~10.14~8.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-devel-debuginfo", rpm:"postgresql10-devel-debuginfo~10.14~8.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-docs", rpm:"postgresql10-docs~10.14~8.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-plperl", rpm:"postgresql10-plperl~10.14~8.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-plperl-debuginfo", rpm:"postgresql10-plperl-debuginfo~10.14~8.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-plpython", rpm:"postgresql10-plpython~10.14~8.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-plpython-debuginfo", rpm:"postgresql10-plpython-debuginfo~10.14~8.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-pltcl", rpm:"postgresql10-pltcl~10.14~8.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-pltcl-debuginfo", rpm:"postgresql10-pltcl-debuginfo~10.14~8.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-server", rpm:"postgresql10-server~10.14~8.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-server-debuginfo", rpm:"postgresql10-server-debuginfo~10.14~8.19.1", rls:"SLES15.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"postgresql10", rpm:"postgresql10~10.14~8.19.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-debuginfo", rpm:"postgresql10-debuginfo~10.14~8.19.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-debugsource", rpm:"postgresql10-debugsource~10.14~8.19.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-contrib", rpm:"postgresql10-contrib~10.14~8.19.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-contrib-debuginfo", rpm:"postgresql10-contrib-debuginfo~10.14~8.19.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-devel", rpm:"postgresql10-devel~10.14~8.19.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-devel-debuginfo", rpm:"postgresql10-devel-debuginfo~10.14~8.19.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-docs", rpm:"postgresql10-docs~10.14~8.19.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-plperl", rpm:"postgresql10-plperl~10.14~8.19.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-plperl-debuginfo", rpm:"postgresql10-plperl-debuginfo~10.14~8.19.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-plpython", rpm:"postgresql10-plpython~10.14~8.19.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-plpython-debuginfo", rpm:"postgresql10-plpython-debuginfo~10.14~8.19.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-pltcl", rpm:"postgresql10-pltcl~10.14~8.19.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-pltcl-debuginfo", rpm:"postgresql10-pltcl-debuginfo~10.14~8.19.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-server", rpm:"postgresql10-server~10.14~8.19.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-server-debuginfo", rpm:"postgresql10-server-debuginfo~10.14~8.19.1", rls:"SLES15.0SP2"))) {
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
