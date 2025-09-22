# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1267.3");
  script_cve_id("CVE-2019-11023");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:59 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-10 13:42:57 +0000 (Wed, 10 Apr 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1267-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1267-3");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191267-3/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'graphviz' package(s) announced via the SUSE-SU-2019:1267-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for graphviz fixes the following issues:

Security issue fixed:

CVE-2019-11023: Fixed a denial of service vulnerability, which was
 caused by a NULL pointer dereference in agroot() (bsc#1132091).");

  script_tag(name:"affected", value:"'graphviz' package(s) on SUSE Linux Enterprise High Availability 15-SP2, SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise Module for Development Tools 15-SP2, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP1, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP2, SUSE Linux Enterprise Module for Server Applications 15-SP2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"graphviz", rpm:"graphviz~2.40.1~6.3.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-debuginfo", rpm:"graphviz-debuginfo~2.40.1~6.3.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-debugsource", rpm:"graphviz-debugsource~2.40.1~6.3.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-devel", rpm:"graphviz-devel~2.40.1~6.3.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-plugins-core", rpm:"graphviz-plugins-core~2.40.1~6.3.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-plugins-core-debuginfo", rpm:"graphviz-plugins-core-debuginfo~2.40.1~6.3.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphviz6", rpm:"libgraphviz6~2.40.1~6.3.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphviz6-debuginfo", rpm:"libgraphviz6-debuginfo~2.40.1~6.3.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-addons-debuginfo", rpm:"graphviz-addons-debuginfo~2.40.1~6.3.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-addons-debugsource", rpm:"graphviz-addons-debugsource~2.40.1~6.3.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-perl", rpm:"graphviz-perl~2.40.1~6.3.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-perl-debuginfo", rpm:"graphviz-perl-debuginfo~2.40.1~6.3.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gnome", rpm:"graphviz-gnome~2.40.1~6.3.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gnome-debuginfo", rpm:"graphviz-gnome-debuginfo~2.40.1~6.3.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-tcl", rpm:"graphviz-tcl~2.40.1~6.3.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-tcl-debuginfo", rpm:"graphviz-tcl-debuginfo~2.40.1~6.3.2", rls:"SLES15.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"graphviz-addons-debuginfo", rpm:"graphviz-addons-debuginfo~2.40.1~6.3.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-addons-debugsource", rpm:"graphviz-addons-debugsource~2.40.1~6.3.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gnome", rpm:"graphviz-gnome~2.40.1~6.3.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-gnome-debuginfo", rpm:"graphviz-gnome-debuginfo~2.40.1~6.3.2", rls:"SLES15.0SP1"))) {
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
