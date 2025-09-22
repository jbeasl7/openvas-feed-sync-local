# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833036");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-32700");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-23 18:10:24 +0000 (Tue, 23 May 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 08:01:53 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for texlive (SUSE-SU-2023:2284-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2284-2");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/4EYGHAEHYF2HOZIWQQLURXVJ6NQQRBNO");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'texlive'
  package(s) announced via the SUSE-SU-2023:2284-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for texlive fixes the following issues:

  * CVE-2023-32700: Fixed arbitrary code execution in LuaTeX (bsc#1211389).

  ##");

  script_tag(name:"affected", value:"'texlive' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"texlive-de-macro-bin", rpm:"texlive-de-macro-bin~2021.20210325.svn17399~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pfarrei-bin", rpm:"texlive-pfarrei-bin~2021.20210325.svn29348~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latex-bin-bin", rpm:"texlive-latex-bin-bin~2021.20210325.svn54358~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-chktex-bin", rpm:"texlive-chktex-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-context-bin", rpm:"texlive-context-bin~2021.20210325.svn34112~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ctanupload-bin", rpm:"texlive-ctanupload-bin~2021.20210325.svn23866~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xpdfopen-bin", rpm:"texlive-xpdfopen-bin~2021.20210325.svn52917~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-musixtnt-bin-debuginfo", rpm:"texlive-musixtnt-bin-debuginfo~2021.20210325.svn50281~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-makeindex-bin", rpm:"texlive-makeindex-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bibtex8-bin-debuginfo", rpm:"texlive-bibtex8-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdflatexpicscale-bin", rpm:"texlive-pdflatexpicscale-bin~2021.20210325.svn41779~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texloganalyser-bin", rpm:"texlive-texloganalyser-bin~2021.20210325.svn13663~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lacheck-bin-debuginfo", rpm:"texlive-lacheck-bin-debuginfo~2021.20210325.svn53999~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-asymptote-bin", rpm:"texlive-asymptote-bin~2021.20210325.svn57890~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texplate-bin", rpm:"texlive-texplate-bin~2021.20210325.svn53444~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tie-bin-debuginfo", rpm:"texlive-tie-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latex-bin-dev-bin", rpm:"texlive-latex-bin-dev-bin~2021.20210325.svn53999~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latexindent-bin", rpm:"texlive-latexindent-bin~2021.20210325.svn32150~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bib2gls-bin", rpm:"texlive-bib2gls-bin~2021.20210325.svn45266~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ptex-bin-debuginfo", rpm:"texlive-ptex-bin-debuginfo~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdftex-quiet-bin", rpm:"texlive-pdftex-quiet-bin~2021.20210325.svn49140~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tikztosvg-bin", rpm:"texlive-tikztosvg-bin~2021.20210325.svn55132~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-authorindex-bin", rpm:"texlive-authorindex-bin~2021.20210325.svn18790~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bundledoc-bin", rpm:"texlive-bundledoc-bin~2021.20210325.svn17794~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lcdftypetools-bin", rpm:"texlive-lcdftypetools-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pedigree-perl-bin", rpm:"texlive-pedigree-perl-bin~2021.20210325.svn25962~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pkfix-bin", rpm:"texlive-pkfix-bin~2021.20210325.svn13364~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pst-pdf-bin", rpm:"texlive-pst-pdf-bin~2021.20210325.svn7838~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mex-bin", rpm:"texlive-mex-bin~2021.20210325.svn3006~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-m-tx-bin-debuginfo", rpm:"texlive-m-tx-bin-debuginfo~2021.20210325.svn50281~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-afm2pl-bin-debuginfo", rpm:"texlive-afm2pl-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-asymptote-bin-debuginfo", rpm:"texlive-asymptote-bin-debuginfo~2021.20210325.svn57890~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ctie-bin-debuginfo", rpm:"texlive-ctie-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-kpathsea-bin", rpm:"texlive-kpathsea-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lacheck-bin", rpm:"texlive-lacheck-bin~2021.20210325.svn53999~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-optex-bin", rpm:"texlive-optex-bin~2021.20210325.svn53804~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-afm2pl-bin", rpm:"texlive-afm2pl-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-make4ht-bin", rpm:"texlive-make4ht-bin~2021.20210325.svn37750~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ps2pk-bin-debuginfo", rpm:"texlive-ps2pk-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvips-bin-debuginfo", rpm:"texlive-dvips-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libptexenc1", rpm:"libptexenc1~1.3.9~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bibexport-bin", rpm:"texlive-bibexport-bin~2021.20210325.svn16219~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-gsftopk-bin-debuginfo", rpm:"texlive-gsftopk-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ctanify-bin", rpm:"texlive-ctanify-bin~2021.20210325.svn24061~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-epspdf-bin", rpm:"texlive-epspdf-bin~2021.20210325.svn29050~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mfware-bin-debuginfo", rpm:"texlive-mfware-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-omegaware-bin", rpm:"texlive-omegaware-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-epstopdf-bin", rpm:"texlive-epstopdf-bin~2021.20210325.svn18336~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pmx-bin-debuginfo", rpm:"texlive-pmx-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-uplatex-bin", rpm:"texlive-uplatex-bin~2021.20210325.svn52800~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pax-bin", rpm:"texlive-pax-bin~2021.20210325.svn10843~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtexlua53-5-debuginfo", rpm:"libtexlua53-5-debuginfo~5.3.6~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-luatex-bin", rpm:"texlive-luatex-bin~2021.20210325.svn58535~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-chklref-bin", rpm:"texlive-chklref-bin~2021.20210325.svn52631~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-yplan-bin", rpm:"texlive-yplan-bin~2021.20210325.svn34398~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texware-bin-debuginfo", rpm:"texlive-texware-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pmx-bin", rpm:"texlive-pmx-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dviljk-bin", rpm:"texlive-dviljk-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-debuginfo", rpm:"texlive-debuginfo~2021.20210325~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xetex-bin-debuginfo", rpm:"texlive-xetex-bin-debuginfo~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-match_parens-bin", rpm:"texlive-match_parens-bin~2021.20210325.svn23500~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texosquery-bin", rpm:"texlive-texosquery-bin~2021.20210325.svn43596~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-debugsource", rpm:"texlive-debugsource~2021.20210325~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-luatex-bin-debuginfo", rpm:"texlive-luatex-bin-debuginfo~2021.20210325.svn58535~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-gregoriotex-bin", rpm:"texlive-gregoriotex-bin~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xetex-bin", rpm:"texlive-xetex-bin~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-autosp-bin", rpm:"texlive-autosp-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-aleph-bin", rpm:"texlive-aleph-bin~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-synctex-bin", rpm:"texlive-synctex-bin~2021.20210325.svn58136~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texliveonfly-bin", rpm:"texlive-texliveonfly-bin~2021.20210325.svn24062~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texlua-devel", rpm:"texlive-texlua-devel~5.3.6~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pythontex-bin", rpm:"texlive-pythontex-bin~2021.20210325.svn31638~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bibtex-bin", rpm:"texlive-bibtex-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsynctex2-debuginfo", rpm:"libsynctex2-debuginfo~1.21~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-multibibliography-bin", rpm:"texlive-multibibliography-bin~2021.20210325.svn30534~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texsis-bin", rpm:"texlive-texsis-bin~2021.20210325.svn3006~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cluttex-bin", rpm:"texlive-cluttex-bin~2021.20210325.svn48871~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latexpand-bin", rpm:"texlive-latexpand-bin~2021.20210325.svn27025~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tex4ebook-bin", rpm:"texlive-tex4ebook-bin~2021.20210325.svn37771~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-fontinst-bin", rpm:"texlive-fontinst-bin~2021.20210325.svn53554~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdfcrop-bin", rpm:"texlive-pdfcrop-bin~2021.20210325.svn14387~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ltxfileinfo-bin", rpm:"texlive-ltxfileinfo-bin~2021.20210325.svn29005~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ttfutils-bin-debuginfo", rpm:"texlive-ttfutils-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dviout-util-bin-debuginfo", rpm:"texlive-dviout-util-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latexfileversion-bin", rpm:"texlive-latexfileversion-bin~2021.20210325.svn25012~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cslatex-bin", rpm:"texlive-cslatex-bin~2021.20210325.svn3006~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-synctex-bin-debuginfo", rpm:"texlive-synctex-bin-debuginfo~2021.20210325.svn58136~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-accfonts-bin", rpm:"texlive-accfonts-bin~2021.20210325.svn12688~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-convbkmk-bin", rpm:"texlive-convbkmk-bin~2021.20210325.svn30408~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dviasm-bin", rpm:"texlive-dviasm-bin~2021.20210325.svn8329~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mflua-bin", rpm:"texlive-mflua-bin~2021.20210325.svn58535~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-amstex-bin", rpm:"texlive-amstex-bin~2021.20210325.svn3006~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-attachfile2-bin", rpm:"texlive-attachfile2-bin~2021.20210325.svn52909~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xelatex-dev-bin", rpm:"texlive-xelatex-dev-bin~2021.20210325.svn53999~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-findhyph-bin", rpm:"texlive-findhyph-bin~2021.20210325.svn14758~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scripts-bin", rpm:"texlive-scripts-bin~2021.20210325.svn55172~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdftex-bin-debuginfo", rpm:"texlive-pdftex-bin-debuginfo~2021.20210325.svn58535~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-wordcount-bin", rpm:"texlive-wordcount-bin~2021.20210325.svn46165~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-fontware-bin-debuginfo", rpm:"texlive-fontware-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ulqda-bin", rpm:"texlive-ulqda-bin~2021.20210325.svn13663~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xindex-bin", rpm:"texlive-xindex-bin~2021.20210325.svn49312~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tex4ht-bin-debuginfo", rpm:"texlive-tex4ht-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mkgrkindex-bin", rpm:"texlive-mkgrkindex-bin~2021.20210325.svn14428~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-uptex-bin-debuginfo", rpm:"texlive-uptex-bin-debuginfo~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cweb-bin", rpm:"texlive-cweb-bin~2021.20210325.svn58136~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-urlbst-bin", rpm:"texlive-urlbst-bin~2021.20210325.svn23262~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bin-devel", rpm:"texlive-bin-devel~2021.20210325~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-a2ping-bin", rpm:"texlive-a2ping-bin~2021.20210325.svn27321~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texware-bin", rpm:"texlive-texware-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-webquiz-bin", rpm:"texlive-webquiz-bin~2021.20210325.svn50419~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tex4ht-bin", rpm:"texlive-tex4ht-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvipdfmx-bin", rpm:"texlive-dvipdfmx-bin~2021.20210325.svn58535~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvisvgm-bin", rpm:"texlive-dvisvgm-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ctie-bin", rpm:"texlive-ctie-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ketcindy-bin", rpm:"texlive-ketcindy-bin~2021.20210325.svn49033~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latex-git-log-bin", rpm:"texlive-latex-git-log-bin~2021.20210325.svn30983~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-metapost-bin-debuginfo", rpm:"texlive-metapost-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pkfix-helper-bin", rpm:"texlive-pkfix-helper-bin~2021.20210325.svn13663~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ctanbib-bin", rpm:"texlive-ctanbib-bin~2021.20210325.svn48478~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ptex-bin", rpm:"texlive-ptex-bin~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdfbook2-bin", rpm:"texlive-pdfbook2-bin~2021.20210325.svn37537~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive", rpm:"texlive~2021.20210325~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latex-papersize-bin", rpm:"texlive-latex-papersize-bin~2021.20210325.svn42296~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-synctex-devel", rpm:"texlive-synctex-devel~1.21~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mf2pt1-bin", rpm:"texlive-mf2pt1-bin~2021.20210325.svn23406~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-splitindex-bin", rpm:"texlive-splitindex-bin~2021.20210325.svn29688~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-velthuis-bin-debuginfo", rpm:"texlive-velthuis-bin-debuginfo~2021.20210325.svn50281~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdfxup-bin", rpm:"texlive-pdfxup-bin~2021.20210325.svn40690~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-purifyeps-bin", rpm:"texlive-purifyeps-bin~2021.20210325.svn13663~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latexdiff-bin", rpm:"texlive-latexdiff-bin~2021.20210325.svn16420~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tpic2pdftex-bin", rpm:"texlive-tpic2pdftex-bin~2021.20210325.svn50281~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtexlua53-5", rpm:"libtexlua53-5~5.3.6~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-luaotfload-bin", rpm:"texlive-luaotfload-bin~2021.20210325.svn34647~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bibtexu-bin", rpm:"texlive-bibtexu-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cjkutils-bin-debuginfo", rpm:"texlive-cjkutils-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ttfutils-bin", rpm:"texlive-ttfutils-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-crossrefware-bin", rpm:"texlive-crossrefware-bin~2021.20210325.svn45927~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-axodraw2-bin", rpm:"texlive-axodraw2-bin~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-detex-bin-debuginfo", rpm:"texlive-detex-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dviinfox-bin", rpm:"texlive-dviinfox-bin~2021.20210325.svn44515~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-listings-ext-bin", rpm:"texlive-listings-ext-bin~2021.20210325.svn15093~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-luajittex-bin", rpm:"texlive-luajittex-bin~2021.20210325.svn58535~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ps2pk-bin", rpm:"texlive-ps2pk-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdftosrc-bin-debuginfo", rpm:"texlive-pdftosrc-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvisvgm-bin-debuginfo", rpm:"texlive-dvisvgm-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texdoctk-bin", rpm:"texlive-texdoctk-bin~2021.20210325.svn29741~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-glossaries-bin", rpm:"texlive-glossaries-bin~2021.20210325.svn37813~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-seetexk-bin", rpm:"texlive-seetexk-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-vlna-bin", rpm:"texlive-vlna-bin~2021.20210325.svn50281~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-patgen-bin", rpm:"texlive-patgen-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-detex-bin", rpm:"texlive-detex-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-seetexk-bin-debuginfo", rpm:"texlive-seetexk-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libptexenc1-debuginfo", rpm:"libptexenc1-debuginfo~1.3.9~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-petri-nets-bin", rpm:"texlive-petri-nets-bin~2021.20210325.svn39165~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-platex-bin", rpm:"texlive-platex-bin~2021.20210325.svn52800~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-metafont-bin-debuginfo", rpm:"texlive-metafont-bin-debuginfo~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-kotex-utils-bin", rpm:"texlive-kotex-utils-bin~2021.20210325.svn32101~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvipng-bin", rpm:"texlive-dvipng-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tie-bin", rpm:"texlive-tie-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texdiff-bin", rpm:"texlive-texdiff-bin~2021.20210325.svn15506~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-metapost-bin", rpm:"texlive-metapost-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xpdfopen-bin-debuginfo", rpm:"texlive-xpdfopen-bin-debuginfo~2021.20210325.svn52917~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-csplain-bin", rpm:"texlive-csplain-bin~2021.20210325.svn50528~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lollipop-bin", rpm:"texlive-lollipop-bin~2021.20210325.svn41465~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsynctex2", rpm:"libsynctex2~1.21~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-axodraw2-bin-debuginfo", rpm:"texlive-axodraw2-bin-debuginfo~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-makeindex-bin-debuginfo", rpm:"texlive-makeindex-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texdef-bin", rpm:"texlive-texdef-bin~2021.20210325.svn45011~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-light-latex-make-bin", rpm:"texlive-light-latex-make-bin~2021.20210325.svn56352~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latexmk-bin", rpm:"texlive-latexmk-bin~2021.20210325.svn10937~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-albatross-bin", rpm:"texlive-albatross-bin~2021.20210325.svn57089~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvicopy-bin", rpm:"texlive-dvicopy-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lilyglyphs-bin", rpm:"texlive-lilyglyphs-bin~2021.20210325.svn31696~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-arara-bin", rpm:"texlive-arara-bin~2021.20210325.svn29036~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-srcredact-bin", rpm:"texlive-srcredact-bin~2021.20210325.svn38710~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvipdfmx-bin-debuginfo", rpm:"texlive-dvipdfmx-bin-debuginfo~2021.20210325.svn58535~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-makedtx-bin", rpm:"texlive-makedtx-bin~2021.20210325.svn38769~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ltximg-bin", rpm:"texlive-ltximg-bin~2021.20210325.svn32346~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pmxchords-bin", rpm:"texlive-pmxchords-bin~2021.20210325.svn32405~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-metafont-bin", rpm:"texlive-metafont-bin~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdfjam-bin", rpm:"texlive-pdfjam-bin~2021.20210325.svn52858~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cjk-gs-integrate-bin", rpm:"texlive-cjk-gs-integrate-bin~2021.20210325.svn37223~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bibtexu-bin-debuginfo", rpm:"texlive-bibtexu-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-typeoutfileinfo-bin", rpm:"texlive-typeoutfileinfo-bin~2021.20210325.svn25648~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mfware-bin", rpm:"texlive-mfware-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-checklistings-bin", rpm:"texlive-checklistings-bin~2021.20210325.svn38300~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-fontware-bin", rpm:"texlive-fontware-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mkpic-bin", rpm:"texlive-mkpic-bin~2021.20210325.svn33688~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-chktex-bin-debuginfo", rpm:"texlive-chktex-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scripts-extra-bin", rpm:"texlive-scripts-extra-bin~2021.20210325.svn53577~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvidvi-bin-debuginfo", rpm:"texlive-dvidvi-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texfot-bin", rpm:"texlive-texfot-bin~2021.20210325.svn33155~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-l3build-bin", rpm:"texlive-l3build-bin~2021.20210325.svn46894~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkpathsea6-debuginfo", rpm:"libkpathsea6-debuginfo~6.3.3~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-svn-multi-bin", rpm:"texlive-svn-multi-bin~2021.20210325.svn13663~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mflua-bin-debuginfo", rpm:"texlive-mflua-bin-debuginfo~2021.20210325.svn58535~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dtl-bin", rpm:"texlive-dtl-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mkjobtexmf-bin", rpm:"texlive-mkjobtexmf-bin~2021.20210325.svn8457~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-vlna-bin-debuginfo", rpm:"texlive-vlna-bin-debuginfo~2021.20210325.svn50281~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ps2eps-bin", rpm:"texlive-ps2eps-bin~2021.20210325.svn50281~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tex-bin", rpm:"texlive-tex-bin~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pygmentex-bin", rpm:"texlive-pygmentex-bin~2021.20210325.svn34996~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-web-bin-debuginfo", rpm:"texlive-web-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-thumbpdf-bin", rpm:"texlive-thumbpdf-bin~2021.20210325.svn6898~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-jfmutil-bin", rpm:"texlive-jfmutil-bin~2021.20210325.svn44835~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ctan-o-mat-bin", rpm:"texlive-ctan-o-mat-bin~2021.20210325.svn46996~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lwarp-bin", rpm:"texlive-lwarp-bin~2021.20210325.svn43292~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ptex-fontmaps-bin", rpm:"texlive-ptex-fontmaps-bin~2021.20210325.svn44206~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-getmap-bin", rpm:"texlive-getmap-bin~2021.20210325.svn34971~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkpathsea6", rpm:"libkpathsea6~6.3.3~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xml2pmx-bin-debuginfo", rpm:"texlive-xml2pmx-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ps2eps-bin-debuginfo", rpm:"texlive-ps2eps-bin-debuginfo~2021.20210325.svn50281~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-luahbtex-bin-debuginfo", rpm:"texlive-luahbtex-bin-debuginfo~2021.20210325.svn58535~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tex-bin-debuginfo", rpm:"texlive-tex-bin-debuginfo~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-kpathsea-devel", rpm:"texlive-kpathsea-devel~6.3.3~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-clojure-pamphlet-bin", rpm:"texlive-clojure-pamphlet-bin~2021.20210325.svn51944~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-fig4latex-bin", rpm:"texlive-fig4latex-bin~2021.20210325.svn14752~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-vpe-bin", rpm:"texlive-vpe-bin~2021.20210325.svn6897~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-musixtex-bin", rpm:"texlive-musixtex-bin~2021.20210325.svn37026~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-autosp-bin-debuginfo", rpm:"texlive-autosp-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-spix-bin", rpm:"texlive-spix-bin~2021.20210325.svn55933~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-fontools-bin", rpm:"texlive-fontools-bin~2021.20210325.svn25997~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xdvi-bin", rpm:"texlive-xdvi-bin~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bibtex8-bin", rpm:"texlive-bibtex8-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvipos-bin", rpm:"texlive-dvipos-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-m-tx-bin", rpm:"texlive-m-tx-bin~2021.20210325.svn50281~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latex2nemeth-bin", rpm:"texlive-latex2nemeth-bin~2021.20210325.svn42300~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mptopdf-bin", rpm:"texlive-mptopdf-bin~2021.20210325.svn18674~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdftex-bin", rpm:"texlive-pdftex-bin~2021.20210325.svn58535~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-luahbtex-bin", rpm:"texlive-luahbtex-bin~2021.20210325.svn58535~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-rubik-bin", rpm:"texlive-rubik-bin~2021.20210325.svn32919~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xdvi-bin-debuginfo", rpm:"texlive-xdvi-bin-debuginfo~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-adhocfilelist-bin", rpm:"texlive-adhocfilelist-bin~2021.20210325.svn28038~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dtxgen-bin", rpm:"texlive-dtxgen-bin~2021.20210325.svn29031~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-hyperxmp-bin", rpm:"texlive-hyperxmp-bin~2021.20210325.svn56984~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texdirflatten-bin", rpm:"texlive-texdirflatten-bin~2021.20210325.svn12782~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-musixtnt-bin", rpm:"texlive-musixtnt-bin~2021.20210325.svn50281~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvicopy-bin-debuginfo", rpm:"texlive-dvicopy-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-aleph-bin-debuginfo", rpm:"texlive-aleph-bin-debuginfo~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-patgen-bin-debuginfo", rpm:"texlive-patgen-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ptexenc-devel", rpm:"texlive-ptexenc-devel~1.3.9~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-velthuis-bin", rpm:"texlive-velthuis-bin~2021.20210325.svn50281~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-web-bin", rpm:"texlive-web-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texcount-bin", rpm:"texlive-texcount-bin~2021.20210325.svn13013~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texdoc-bin", rpm:"texlive-texdoc-bin~2021.20210325.svn47948~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dosepsbin-bin", rpm:"texlive-dosepsbin-bin~2021.20210325.svn24759~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvipos-bin-debuginfo", rpm:"texlive-dvipos-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-exceltex-bin", rpm:"texlive-exceltex-bin~2021.20210325.svn25860~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lcdftypetools-bin-debuginfo", rpm:"texlive-lcdftypetools-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-sty2dtx-bin", rpm:"texlive-sty2dtx-bin~2021.20210325.svn21215~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cachepic-bin", rpm:"texlive-cachepic-bin~2021.20210325.svn15543~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dviout-util-bin", rpm:"texlive-dviout-util-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-gregoriotex-bin-debuginfo", rpm:"texlive-gregoriotex-bin-debuginfo~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cjkutils-bin", rpm:"texlive-cjkutils-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvidvi-bin", rpm:"texlive-dvidvi-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latex2man-bin", rpm:"texlive-latex2man-bin~2021.20210325.svn13663~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdftosrc-bin", rpm:"texlive-pdftosrc-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dviljk-bin-debuginfo", rpm:"texlive-dviljk-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ptex2pdf-bin", rpm:"texlive-ptex2pdf-bin~2021.20210325.svn29335~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-git-latexdiff-bin", rpm:"texlive-git-latexdiff-bin~2021.20210325.svn54732~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-gsftopk-bin", rpm:"texlive-gsftopk-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-jadetex-bin", rpm:"texlive-jadetex-bin~2021.20210325.svn3006~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-kpathsea-bin-debuginfo", rpm:"texlive-kpathsea-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-listbib-bin", rpm:"texlive-listbib-bin~2021.20210325.svn26126~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mltex-bin", rpm:"texlive-mltex-bin~2021.20210325.svn3006~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-uptex-bin", rpm:"texlive-uptex-bin~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-fragmaster-bin", rpm:"texlive-fragmaster-bin~2021.20210325.svn13663~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xmltex-bin", rpm:"texlive-xmltex-bin~2021.20210325.svn3006~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-checkcites-bin", rpm:"texlive-checkcites-bin~2021.20210325.svn25623~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dtl-bin-debuginfo", rpm:"texlive-dtl-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mathspic-bin", rpm:"texlive-mathspic-bin~2021.20210325.svn23661~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bibtex-bin-debuginfo", rpm:"texlive-bibtex-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-omegaware-bin-debuginfo", rpm:"texlive-omegaware-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pst2pdf-bin", rpm:"texlive-pst2pdf-bin~2021.20210325.svn29333~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cweb-bin-debuginfo", rpm:"texlive-cweb-bin-debuginfo~2021.20210325.svn58136~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-eplain-bin", rpm:"texlive-eplain-bin~2021.20210325.svn3006~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cyrillic-bin-bin", rpm:"texlive-cyrillic-bin-bin~2021.20210325.svn53554~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xml2pmx-bin", rpm:"texlive-xml2pmx-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvipng-bin-debuginfo", rpm:"texlive-dvipng-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-perltex-bin", rpm:"texlive-perltex-bin~2021.20210325.svn16181~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvips-bin", rpm:"texlive-dvips-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texluajit-devel", rpm:"texlive-texluajit-devel~2.1.0beta3~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtexluajit2", rpm:"libtexluajit2~2.1.0beta3~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-luajittex-bin-debuginfo", rpm:"texlive-luajittex-bin-debuginfo~2021.20210325.svn58535~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtexluajit2-debuginfo", rpm:"libtexluajit2-debuginfo~2.1.0beta3~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-biber", rpm:"perl-biber~2021.20210325.svn30357~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-diadia-bin", rpm:"texlive-diadia-bin~2021.20210325.svn37645~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-biber-bin", rpm:"texlive-biber-bin~2021.20210325.svn57273~150400.31.3.1##", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-de-macro-bin", rpm:"texlive-de-macro-bin~2021.20210325.svn17399~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pfarrei-bin", rpm:"texlive-pfarrei-bin~2021.20210325.svn29348~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latex-bin-bin", rpm:"texlive-latex-bin-bin~2021.20210325.svn54358~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-chktex-bin", rpm:"texlive-chktex-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-context-bin", rpm:"texlive-context-bin~2021.20210325.svn34112~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ctanupload-bin", rpm:"texlive-ctanupload-bin~2021.20210325.svn23866~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xpdfopen-bin", rpm:"texlive-xpdfopen-bin~2021.20210325.svn52917~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-musixtnt-bin-debuginfo", rpm:"texlive-musixtnt-bin-debuginfo~2021.20210325.svn50281~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-makeindex-bin", rpm:"texlive-makeindex-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bibtex8-bin-debuginfo", rpm:"texlive-bibtex8-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdflatexpicscale-bin", rpm:"texlive-pdflatexpicscale-bin~2021.20210325.svn41779~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texloganalyser-bin", rpm:"texlive-texloganalyser-bin~2021.20210325.svn13663~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lacheck-bin-debuginfo", rpm:"texlive-lacheck-bin-debuginfo~2021.20210325.svn53999~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-asymptote-bin", rpm:"texlive-asymptote-bin~2021.20210325.svn57890~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texplate-bin", rpm:"texlive-texplate-bin~2021.20210325.svn53444~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tie-bin-debuginfo", rpm:"texlive-tie-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latex-bin-dev-bin", rpm:"texlive-latex-bin-dev-bin~2021.20210325.svn53999~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latexindent-bin", rpm:"texlive-latexindent-bin~2021.20210325.svn32150~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bib2gls-bin", rpm:"texlive-bib2gls-bin~2021.20210325.svn45266~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ptex-bin-debuginfo", rpm:"texlive-ptex-bin-debuginfo~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdftex-quiet-bin", rpm:"texlive-pdftex-quiet-bin~2021.20210325.svn49140~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tikztosvg-bin", rpm:"texlive-tikztosvg-bin~2021.20210325.svn55132~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-authorindex-bin", rpm:"texlive-authorindex-bin~2021.20210325.svn18790~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bundledoc-bin", rpm:"texlive-bundledoc-bin~2021.20210325.svn17794~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lcdftypetools-bin", rpm:"texlive-lcdftypetools-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pedigree-perl-bin", rpm:"texlive-pedigree-perl-bin~2021.20210325.svn25962~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pkfix-bin", rpm:"texlive-pkfix-bin~2021.20210325.svn13364~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pst-pdf-bin", rpm:"texlive-pst-pdf-bin~2021.20210325.svn7838~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mex-bin", rpm:"texlive-mex-bin~2021.20210325.svn3006~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-m-tx-bin-debuginfo", rpm:"texlive-m-tx-bin-debuginfo~2021.20210325.svn50281~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-afm2pl-bin-debuginfo", rpm:"texlive-afm2pl-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-asymptote-bin-debuginfo", rpm:"texlive-asymptote-bin-debuginfo~2021.20210325.svn57890~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ctie-bin-debuginfo", rpm:"texlive-ctie-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-kpathsea-bin", rpm:"texlive-kpathsea-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lacheck-bin", rpm:"texlive-lacheck-bin~2021.20210325.svn53999~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-optex-bin", rpm:"texlive-optex-bin~2021.20210325.svn53804~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-afm2pl-bin", rpm:"texlive-afm2pl-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-make4ht-bin", rpm:"texlive-make4ht-bin~2021.20210325.svn37750~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ps2pk-bin-debuginfo", rpm:"texlive-ps2pk-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvips-bin-debuginfo", rpm:"texlive-dvips-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libptexenc1", rpm:"libptexenc1~1.3.9~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bibexport-bin", rpm:"texlive-bibexport-bin~2021.20210325.svn16219~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-gsftopk-bin-debuginfo", rpm:"texlive-gsftopk-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ctanify-bin", rpm:"texlive-ctanify-bin~2021.20210325.svn24061~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-epspdf-bin", rpm:"texlive-epspdf-bin~2021.20210325.svn29050~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mfware-bin-debuginfo", rpm:"texlive-mfware-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-omegaware-bin", rpm:"texlive-omegaware-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-epstopdf-bin", rpm:"texlive-epstopdf-bin~2021.20210325.svn18336~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pmx-bin-debuginfo", rpm:"texlive-pmx-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-uplatex-bin", rpm:"texlive-uplatex-bin~2021.20210325.svn52800~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pax-bin", rpm:"texlive-pax-bin~2021.20210325.svn10843~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtexlua53-5-debuginfo", rpm:"libtexlua53-5-debuginfo~5.3.6~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-luatex-bin", rpm:"texlive-luatex-bin~2021.20210325.svn58535~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-chklref-bin", rpm:"texlive-chklref-bin~2021.20210325.svn52631~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-yplan-bin", rpm:"texlive-yplan-bin~2021.20210325.svn34398~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texware-bin-debuginfo", rpm:"texlive-texware-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pmx-bin", rpm:"texlive-pmx-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dviljk-bin", rpm:"texlive-dviljk-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-debuginfo", rpm:"texlive-debuginfo~2021.20210325~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xetex-bin-debuginfo", rpm:"texlive-xetex-bin-debuginfo~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-match_parens-bin", rpm:"texlive-match_parens-bin~2021.20210325.svn23500~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texosquery-bin", rpm:"texlive-texosquery-bin~2021.20210325.svn43596~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-debugsource", rpm:"texlive-debugsource~2021.20210325~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-luatex-bin-debuginfo", rpm:"texlive-luatex-bin-debuginfo~2021.20210325.svn58535~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-gregoriotex-bin", rpm:"texlive-gregoriotex-bin~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xetex-bin", rpm:"texlive-xetex-bin~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-autosp-bin", rpm:"texlive-autosp-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-aleph-bin", rpm:"texlive-aleph-bin~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-synctex-bin", rpm:"texlive-synctex-bin~2021.20210325.svn58136~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texliveonfly-bin", rpm:"texlive-texliveonfly-bin~2021.20210325.svn24062~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texlua-devel", rpm:"texlive-texlua-devel~5.3.6~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pythontex-bin", rpm:"texlive-pythontex-bin~2021.20210325.svn31638~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bibtex-bin", rpm:"texlive-bibtex-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsynctex2-debuginfo", rpm:"libsynctex2-debuginfo~1.21~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-multibibliography-bin", rpm:"texlive-multibibliography-bin~2021.20210325.svn30534~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texsis-bin", rpm:"texlive-texsis-bin~2021.20210325.svn3006~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cluttex-bin", rpm:"texlive-cluttex-bin~2021.20210325.svn48871~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latexpand-bin", rpm:"texlive-latexpand-bin~2021.20210325.svn27025~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tex4ebook-bin", rpm:"texlive-tex4ebook-bin~2021.20210325.svn37771~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-fontinst-bin", rpm:"texlive-fontinst-bin~2021.20210325.svn53554~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdfcrop-bin", rpm:"texlive-pdfcrop-bin~2021.20210325.svn14387~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ltxfileinfo-bin", rpm:"texlive-ltxfileinfo-bin~2021.20210325.svn29005~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ttfutils-bin-debuginfo", rpm:"texlive-ttfutils-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dviout-util-bin-debuginfo", rpm:"texlive-dviout-util-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latexfileversion-bin", rpm:"texlive-latexfileversion-bin~2021.20210325.svn25012~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cslatex-bin", rpm:"texlive-cslatex-bin~2021.20210325.svn3006~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-synctex-bin-debuginfo", rpm:"texlive-synctex-bin-debuginfo~2021.20210325.svn58136~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-accfonts-bin", rpm:"texlive-accfonts-bin~2021.20210325.svn12688~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-convbkmk-bin", rpm:"texlive-convbkmk-bin~2021.20210325.svn30408~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dviasm-bin", rpm:"texlive-dviasm-bin~2021.20210325.svn8329~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mflua-bin", rpm:"texlive-mflua-bin~2021.20210325.svn58535~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-amstex-bin", rpm:"texlive-amstex-bin~2021.20210325.svn3006~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-attachfile2-bin", rpm:"texlive-attachfile2-bin~2021.20210325.svn52909~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xelatex-dev-bin", rpm:"texlive-xelatex-dev-bin~2021.20210325.svn53999~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-findhyph-bin", rpm:"texlive-findhyph-bin~2021.20210325.svn14758~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scripts-bin", rpm:"texlive-scripts-bin~2021.20210325.svn55172~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdftex-bin-debuginfo", rpm:"texlive-pdftex-bin-debuginfo~2021.20210325.svn58535~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-wordcount-bin", rpm:"texlive-wordcount-bin~2021.20210325.svn46165~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-fontware-bin-debuginfo", rpm:"texlive-fontware-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ulqda-bin", rpm:"texlive-ulqda-bin~2021.20210325.svn13663~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xindex-bin", rpm:"texlive-xindex-bin~2021.20210325.svn49312~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tex4ht-bin-debuginfo", rpm:"texlive-tex4ht-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mkgrkindex-bin", rpm:"texlive-mkgrkindex-bin~2021.20210325.svn14428~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-uptex-bin-debuginfo", rpm:"texlive-uptex-bin-debuginfo~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cweb-bin", rpm:"texlive-cweb-bin~2021.20210325.svn58136~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-urlbst-bin", rpm:"texlive-urlbst-bin~2021.20210325.svn23262~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bin-devel", rpm:"texlive-bin-devel~2021.20210325~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-a2ping-bin", rpm:"texlive-a2ping-bin~2021.20210325.svn27321~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texware-bin", rpm:"texlive-texware-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-webquiz-bin", rpm:"texlive-webquiz-bin~2021.20210325.svn50419~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tex4ht-bin", rpm:"texlive-tex4ht-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvipdfmx-bin", rpm:"texlive-dvipdfmx-bin~2021.20210325.svn58535~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvisvgm-bin", rpm:"texlive-dvisvgm-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ctie-bin", rpm:"texlive-ctie-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ketcindy-bin", rpm:"texlive-ketcindy-bin~2021.20210325.svn49033~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latex-git-log-bin", rpm:"texlive-latex-git-log-bin~2021.20210325.svn30983~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-metapost-bin-debuginfo", rpm:"texlive-metapost-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pkfix-helper-bin", rpm:"texlive-pkfix-helper-bin~2021.20210325.svn13663~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ctanbib-bin", rpm:"texlive-ctanbib-bin~2021.20210325.svn48478~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ptex-bin", rpm:"texlive-ptex-bin~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdfbook2-bin", rpm:"texlive-pdfbook2-bin~2021.20210325.svn37537~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive", rpm:"texlive~2021.20210325~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latex-papersize-bin", rpm:"texlive-latex-papersize-bin~2021.20210325.svn42296~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-synctex-devel", rpm:"texlive-synctex-devel~1.21~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mf2pt1-bin", rpm:"texlive-mf2pt1-bin~2021.20210325.svn23406~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-splitindex-bin", rpm:"texlive-splitindex-bin~2021.20210325.svn29688~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-velthuis-bin-debuginfo", rpm:"texlive-velthuis-bin-debuginfo~2021.20210325.svn50281~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdfxup-bin", rpm:"texlive-pdfxup-bin~2021.20210325.svn40690~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-purifyeps-bin", rpm:"texlive-purifyeps-bin~2021.20210325.svn13663~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latexdiff-bin", rpm:"texlive-latexdiff-bin~2021.20210325.svn16420~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tpic2pdftex-bin", rpm:"texlive-tpic2pdftex-bin~2021.20210325.svn50281~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtexlua53-5", rpm:"libtexlua53-5~5.3.6~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-luaotfload-bin", rpm:"texlive-luaotfload-bin~2021.20210325.svn34647~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bibtexu-bin", rpm:"texlive-bibtexu-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cjkutils-bin-debuginfo", rpm:"texlive-cjkutils-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ttfutils-bin", rpm:"texlive-ttfutils-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-crossrefware-bin", rpm:"texlive-crossrefware-bin~2021.20210325.svn45927~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-axodraw2-bin", rpm:"texlive-axodraw2-bin~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-detex-bin-debuginfo", rpm:"texlive-detex-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dviinfox-bin", rpm:"texlive-dviinfox-bin~2021.20210325.svn44515~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-listings-ext-bin", rpm:"texlive-listings-ext-bin~2021.20210325.svn15093~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-luajittex-bin", rpm:"texlive-luajittex-bin~2021.20210325.svn58535~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ps2pk-bin", rpm:"texlive-ps2pk-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdftosrc-bin-debuginfo", rpm:"texlive-pdftosrc-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvisvgm-bin-debuginfo", rpm:"texlive-dvisvgm-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texdoctk-bin", rpm:"texlive-texdoctk-bin~2021.20210325.svn29741~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-glossaries-bin", rpm:"texlive-glossaries-bin~2021.20210325.svn37813~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-seetexk-bin", rpm:"texlive-seetexk-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-vlna-bin", rpm:"texlive-vlna-bin~2021.20210325.svn50281~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-patgen-bin", rpm:"texlive-patgen-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-detex-bin", rpm:"texlive-detex-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-seetexk-bin-debuginfo", rpm:"texlive-seetexk-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libptexenc1-debuginfo", rpm:"libptexenc1-debuginfo~1.3.9~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-petri-nets-bin", rpm:"texlive-petri-nets-bin~2021.20210325.svn39165~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-platex-bin", rpm:"texlive-platex-bin~2021.20210325.svn52800~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-metafont-bin-debuginfo", rpm:"texlive-metafont-bin-debuginfo~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-kotex-utils-bin", rpm:"texlive-kotex-utils-bin~2021.20210325.svn32101~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvipng-bin", rpm:"texlive-dvipng-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tie-bin", rpm:"texlive-tie-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texdiff-bin", rpm:"texlive-texdiff-bin~2021.20210325.svn15506~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-metapost-bin", rpm:"texlive-metapost-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xpdfopen-bin-debuginfo", rpm:"texlive-xpdfopen-bin-debuginfo~2021.20210325.svn52917~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-csplain-bin", rpm:"texlive-csplain-bin~2021.20210325.svn50528~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lollipop-bin", rpm:"texlive-lollipop-bin~2021.20210325.svn41465~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsynctex2", rpm:"libsynctex2~1.21~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-axodraw2-bin-debuginfo", rpm:"texlive-axodraw2-bin-debuginfo~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-makeindex-bin-debuginfo", rpm:"texlive-makeindex-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texdef-bin", rpm:"texlive-texdef-bin~2021.20210325.svn45011~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-light-latex-make-bin", rpm:"texlive-light-latex-make-bin~2021.20210325.svn56352~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latexmk-bin", rpm:"texlive-latexmk-bin~2021.20210325.svn10937~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-albatross-bin", rpm:"texlive-albatross-bin~2021.20210325.svn57089~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvicopy-bin", rpm:"texlive-dvicopy-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lilyglyphs-bin", rpm:"texlive-lilyglyphs-bin~2021.20210325.svn31696~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-arara-bin", rpm:"texlive-arara-bin~2021.20210325.svn29036~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-srcredact-bin", rpm:"texlive-srcredact-bin~2021.20210325.svn38710~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvipdfmx-bin-debuginfo", rpm:"texlive-dvipdfmx-bin-debuginfo~2021.20210325.svn58535~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-makedtx-bin", rpm:"texlive-makedtx-bin~2021.20210325.svn38769~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ltximg-bin", rpm:"texlive-ltximg-bin~2021.20210325.svn32346~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pmxchords-bin", rpm:"texlive-pmxchords-bin~2021.20210325.svn32405~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-metafont-bin", rpm:"texlive-metafont-bin~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdfjam-bin", rpm:"texlive-pdfjam-bin~2021.20210325.svn52858~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cjk-gs-integrate-bin", rpm:"texlive-cjk-gs-integrate-bin~2021.20210325.svn37223~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bibtexu-bin-debuginfo", rpm:"texlive-bibtexu-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-typeoutfileinfo-bin", rpm:"texlive-typeoutfileinfo-bin~2021.20210325.svn25648~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mfware-bin", rpm:"texlive-mfware-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-checklistings-bin", rpm:"texlive-checklistings-bin~2021.20210325.svn38300~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-fontware-bin", rpm:"texlive-fontware-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mkpic-bin", rpm:"texlive-mkpic-bin~2021.20210325.svn33688~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-chktex-bin-debuginfo", rpm:"texlive-chktex-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scripts-extra-bin", rpm:"texlive-scripts-extra-bin~2021.20210325.svn53577~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvidvi-bin-debuginfo", rpm:"texlive-dvidvi-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texfot-bin", rpm:"texlive-texfot-bin~2021.20210325.svn33155~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-l3build-bin", rpm:"texlive-l3build-bin~2021.20210325.svn46894~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkpathsea6-debuginfo", rpm:"libkpathsea6-debuginfo~6.3.3~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-svn-multi-bin", rpm:"texlive-svn-multi-bin~2021.20210325.svn13663~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mflua-bin-debuginfo", rpm:"texlive-mflua-bin-debuginfo~2021.20210325.svn58535~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dtl-bin", rpm:"texlive-dtl-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mkjobtexmf-bin", rpm:"texlive-mkjobtexmf-bin~2021.20210325.svn8457~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-vlna-bin-debuginfo", rpm:"texlive-vlna-bin-debuginfo~2021.20210325.svn50281~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ps2eps-bin", rpm:"texlive-ps2eps-bin~2021.20210325.svn50281~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tex-bin", rpm:"texlive-tex-bin~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pygmentex-bin", rpm:"texlive-pygmentex-bin~2021.20210325.svn34996~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-web-bin-debuginfo", rpm:"texlive-web-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-thumbpdf-bin", rpm:"texlive-thumbpdf-bin~2021.20210325.svn6898~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-jfmutil-bin", rpm:"texlive-jfmutil-bin~2021.20210325.svn44835~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ctan-o-mat-bin", rpm:"texlive-ctan-o-mat-bin~2021.20210325.svn46996~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lwarp-bin", rpm:"texlive-lwarp-bin~2021.20210325.svn43292~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ptex-fontmaps-bin", rpm:"texlive-ptex-fontmaps-bin~2021.20210325.svn44206~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-getmap-bin", rpm:"texlive-getmap-bin~2021.20210325.svn34971~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkpathsea6", rpm:"libkpathsea6~6.3.3~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xml2pmx-bin-debuginfo", rpm:"texlive-xml2pmx-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ps2eps-bin-debuginfo", rpm:"texlive-ps2eps-bin-debuginfo~2021.20210325.svn50281~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-luahbtex-bin-debuginfo", rpm:"texlive-luahbtex-bin-debuginfo~2021.20210325.svn58535~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tex-bin-debuginfo", rpm:"texlive-tex-bin-debuginfo~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-kpathsea-devel", rpm:"texlive-kpathsea-devel~6.3.3~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-clojure-pamphlet-bin", rpm:"texlive-clojure-pamphlet-bin~2021.20210325.svn51944~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-fig4latex-bin", rpm:"texlive-fig4latex-bin~2021.20210325.svn14752~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-vpe-bin", rpm:"texlive-vpe-bin~2021.20210325.svn6897~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-musixtex-bin", rpm:"texlive-musixtex-bin~2021.20210325.svn37026~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-autosp-bin-debuginfo", rpm:"texlive-autosp-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-spix-bin", rpm:"texlive-spix-bin~2021.20210325.svn55933~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-fontools-bin", rpm:"texlive-fontools-bin~2021.20210325.svn25997~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xdvi-bin", rpm:"texlive-xdvi-bin~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bibtex8-bin", rpm:"texlive-bibtex8-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvipos-bin", rpm:"texlive-dvipos-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-m-tx-bin", rpm:"texlive-m-tx-bin~2021.20210325.svn50281~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latex2nemeth-bin", rpm:"texlive-latex2nemeth-bin~2021.20210325.svn42300~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mptopdf-bin", rpm:"texlive-mptopdf-bin~2021.20210325.svn18674~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdftex-bin", rpm:"texlive-pdftex-bin~2021.20210325.svn58535~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-luahbtex-bin", rpm:"texlive-luahbtex-bin~2021.20210325.svn58535~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-rubik-bin", rpm:"texlive-rubik-bin~2021.20210325.svn32919~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xdvi-bin-debuginfo", rpm:"texlive-xdvi-bin-debuginfo~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-adhocfilelist-bin", rpm:"texlive-adhocfilelist-bin~2021.20210325.svn28038~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dtxgen-bin", rpm:"texlive-dtxgen-bin~2021.20210325.svn29031~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-hyperxmp-bin", rpm:"texlive-hyperxmp-bin~2021.20210325.svn56984~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texdirflatten-bin", rpm:"texlive-texdirflatten-bin~2021.20210325.svn12782~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-musixtnt-bin", rpm:"texlive-musixtnt-bin~2021.20210325.svn50281~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvicopy-bin-debuginfo", rpm:"texlive-dvicopy-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-aleph-bin-debuginfo", rpm:"texlive-aleph-bin-debuginfo~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-patgen-bin-debuginfo", rpm:"texlive-patgen-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ptexenc-devel", rpm:"texlive-ptexenc-devel~1.3.9~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-velthuis-bin", rpm:"texlive-velthuis-bin~2021.20210325.svn50281~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-web-bin", rpm:"texlive-web-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texcount-bin", rpm:"texlive-texcount-bin~2021.20210325.svn13013~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texdoc-bin", rpm:"texlive-texdoc-bin~2021.20210325.svn47948~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dosepsbin-bin", rpm:"texlive-dosepsbin-bin~2021.20210325.svn24759~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvipos-bin-debuginfo", rpm:"texlive-dvipos-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-exceltex-bin", rpm:"texlive-exceltex-bin~2021.20210325.svn25860~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lcdftypetools-bin-debuginfo", rpm:"texlive-lcdftypetools-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-sty2dtx-bin", rpm:"texlive-sty2dtx-bin~2021.20210325.svn21215~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cachepic-bin", rpm:"texlive-cachepic-bin~2021.20210325.svn15543~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dviout-util-bin", rpm:"texlive-dviout-util-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-gregoriotex-bin-debuginfo", rpm:"texlive-gregoriotex-bin-debuginfo~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cjkutils-bin", rpm:"texlive-cjkutils-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvidvi-bin", rpm:"texlive-dvidvi-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latex2man-bin", rpm:"texlive-latex2man-bin~2021.20210325.svn13663~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdftosrc-bin", rpm:"texlive-pdftosrc-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dviljk-bin-debuginfo", rpm:"texlive-dviljk-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ptex2pdf-bin", rpm:"texlive-ptex2pdf-bin~2021.20210325.svn29335~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-git-latexdiff-bin", rpm:"texlive-git-latexdiff-bin~2021.20210325.svn54732~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-gsftopk-bin", rpm:"texlive-gsftopk-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-jadetex-bin", rpm:"texlive-jadetex-bin~2021.20210325.svn3006~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-kpathsea-bin-debuginfo", rpm:"texlive-kpathsea-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-listbib-bin", rpm:"texlive-listbib-bin~2021.20210325.svn26126~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mltex-bin", rpm:"texlive-mltex-bin~2021.20210325.svn3006~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-uptex-bin", rpm:"texlive-uptex-bin~2021.20210325.svn58378~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-fragmaster-bin", rpm:"texlive-fragmaster-bin~2021.20210325.svn13663~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xmltex-bin", rpm:"texlive-xmltex-bin~2021.20210325.svn3006~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-checkcites-bin", rpm:"texlive-checkcites-bin~2021.20210325.svn25623~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dtl-bin-debuginfo", rpm:"texlive-dtl-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mathspic-bin", rpm:"texlive-mathspic-bin~2021.20210325.svn23661~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bibtex-bin-debuginfo", rpm:"texlive-bibtex-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-omegaware-bin-debuginfo", rpm:"texlive-omegaware-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pst2pdf-bin", rpm:"texlive-pst2pdf-bin~2021.20210325.svn29333~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cweb-bin-debuginfo", rpm:"texlive-cweb-bin-debuginfo~2021.20210325.svn58136~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-eplain-bin", rpm:"texlive-eplain-bin~2021.20210325.svn3006~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cyrillic-bin-bin", rpm:"texlive-cyrillic-bin-bin~2021.20210325.svn53554~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xml2pmx-bin", rpm:"texlive-xml2pmx-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvipng-bin-debuginfo", rpm:"texlive-dvipng-bin-debuginfo~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-perltex-bin", rpm:"texlive-perltex-bin~2021.20210325.svn16181~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvips-bin", rpm:"texlive-dvips-bin~2021.20210325.svn57878~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texluajit-devel", rpm:"texlive-texluajit-devel~2.1.0beta3~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtexluajit2", rpm:"libtexluajit2~2.1.0beta3~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-luajittex-bin-debuginfo", rpm:"texlive-luajittex-bin-debuginfo~2021.20210325.svn58535~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtexluajit2-debuginfo", rpm:"libtexluajit2-debuginfo~2.1.0beta3~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-biber", rpm:"perl-biber~2021.20210325.svn30357~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-diadia-bin", rpm:"texlive-diadia-bin~2021.20210325.svn37645~150400.31.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-biber-bin", rpm:"texlive-biber-bin~2021.20210325.svn57273~150400.31.3.1##", rls:"openSUSELeap15.5"))) {
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