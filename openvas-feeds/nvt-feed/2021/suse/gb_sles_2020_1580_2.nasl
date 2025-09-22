# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1580.2");
  script_cve_id("CVE-2020-8016", "CVE-2020-8017");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:59 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-06 14:16:18 +0000 (Mon, 06 Apr 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1580-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1580-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201580-2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'texlive-filesystem' package(s) announced via the SUSE-SU-2020:1580-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for texlive-filesystem fixes the following issues:

Security issues fixed:

CVE-2020-8016: Fixed a race condition in the spec file (bsc#1159740).

CVE-2020-8017: Fixed a race condition on a cron job (bsc#1158910).");

  script_tag(name:"affected", value:"'texlive-filesystem' package(s) on SUSE Linux Enterprise Module for Desktop Applications 15-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-basic", rpm:"texlive-collection-basic~2017.135.svn41616~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-bibtexextra", rpm:"texlive-collection-bibtexextra~2017.135.svn44385~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-binextra", rpm:"texlive-collection-binextra~2017.135.svn44515~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-context", rpm:"texlive-collection-context~2017.135.svn42330~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-fontsextra", rpm:"texlive-collection-fontsextra~2017.135.svn43356~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-fontsrecommended", rpm:"texlive-collection-fontsrecommended~2017.135.svn35830~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-fontutils", rpm:"texlive-collection-fontutils~2017.135.svn37105~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-formatsextra", rpm:"texlive-collection-formatsextra~2017.135.svn44177~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-games", rpm:"texlive-collection-games~2017.135.svn42992~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-humanities", rpm:"texlive-collection-humanities~2017.135.svn42268~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langarabic", rpm:"texlive-collection-langarabic~2017.135.svn44496~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langchinese", rpm:"texlive-collection-langchinese~2017.135.svn42675~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langcjk", rpm:"texlive-collection-langcjk~2017.135.svn43009~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langcyrillic", rpm:"texlive-collection-langcyrillic~2017.135.svn44401~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langczechslovak", rpm:"texlive-collection-langczechslovak~2017.135.svn32550~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langenglish", rpm:"texlive-collection-langenglish~2017.135.svn43650~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langeuropean", rpm:"texlive-collection-langeuropean~2017.135.svn44414~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langfrench", rpm:"texlive-collection-langfrench~2017.135.svn40375~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langgerman", rpm:"texlive-collection-langgerman~2017.135.svn42045~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langgreek", rpm:"texlive-collection-langgreek~2017.135.svn44192~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langitalian", rpm:"texlive-collection-langitalian~2017.135.svn30372~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langjapanese", rpm:"texlive-collection-langjapanese~2017.135.svn44554~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langkorean", rpm:"texlive-collection-langkorean~2017.135.svn42106~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langother", rpm:"texlive-collection-langother~2017.135.svn44414~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langpolish", rpm:"texlive-collection-langpolish~2017.135.svn44371~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langportuguese", rpm:"texlive-collection-langportuguese~2017.135.svn30962~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langspanish", rpm:"texlive-collection-langspanish~2017.135.svn40587~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-latex", rpm:"texlive-collection-latex~2017.135.svn41614~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-latexextra", rpm:"texlive-collection-latexextra~2017.135.svn44544~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-latexrecommended", rpm:"texlive-collection-latexrecommended~2017.135.svn44177~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-luatex", rpm:"texlive-collection-luatex~2017.135.svn44500~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-mathscience", rpm:"texlive-collection-mathscience~2017.135.svn44396~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-metapost", rpm:"texlive-collection-metapost~2017.135.svn44297~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-music", rpm:"texlive-collection-music~2017.135.svn40561~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-pictures", rpm:"texlive-collection-pictures~2017.135.svn44395~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-plaingeneric", rpm:"texlive-collection-plaingeneric~2017.135.svn44177~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-pstricks", rpm:"texlive-collection-pstricks~2017.135.svn44460~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-publishers", rpm:"texlive-collection-publishers~2017.135.svn44485~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-xetex", rpm:"texlive-collection-xetex~2017.135.svn43059~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-devel", rpm:"texlive-devel~2017.135~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-extratools", rpm:"texlive-extratools~2017.135~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-filesystem", rpm:"texlive-filesystem~2017.135~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scheme-basic", rpm:"texlive-scheme-basic~2017.135.svn25923~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scheme-context", rpm:"texlive-scheme-context~2017.135.svn35799~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scheme-full", rpm:"texlive-scheme-full~2017.135.svn44177~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scheme-gust", rpm:"texlive-scheme-gust~2017.135.svn44177~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scheme-infraonly", rpm:"texlive-scheme-infraonly~2017.135.svn41515~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scheme-medium", rpm:"texlive-scheme-medium~2017.135.svn44177~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scheme-minimal", rpm:"texlive-scheme-minimal~2017.135.svn13822~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scheme-small", rpm:"texlive-scheme-small~2017.135.svn41825~9.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scheme-tetex", rpm:"texlive-scheme-tetex~2017.135.svn44187~9.12.1", rls:"SLES15.0SP2"))) {
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
