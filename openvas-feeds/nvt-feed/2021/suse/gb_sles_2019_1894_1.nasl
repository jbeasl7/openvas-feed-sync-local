# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1894.1");
  script_cve_id("CVE-2018-16858");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:21 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-25 18:29:00 +0000 (Mon, 25 Mar 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1894-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1894-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191894-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'LibreOffice' package(s) announced via the SUSE-SU-2019:1894-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libreoffice and libraries fixes the following issues:

LibreOffice was updated to 6.2.5.2 (fate#327121 bsc#1128845 bsc#1123455),
bringing lots of bug and stability fixes.

Additional bugfixes:
If there is no firebird engine we still need java to run hsqldb
 (bsc#1135189)

PPTX: Rectangle turns from green to blue and loses transparency when
 transparency is set (bsc#1135228)

Slide deck compression doesn't, hmm, compress too much (bsc#1127760)

Psychedelic graphics in LibreOffice (but not PowerPoint) (bsc#1124869)

Image from PPTX shown in a square, not a circle (bsc#1121874)

libixion was updated to 0.14.1:
Updated for new orcus

liborcus was updated to 0.14.1:
Boost 1.67 support

Various cell handling issues fixed



libwps was updated to 0.4.10:
QuattroPro: add parser of .qwp files

all: support complex encoding

mdds was updated to 1.4.3:
Api change to 1.4

More multivector operations and tweaks

Various multi vector fixes

flat_segment_tree: add segment iterator and functions

fix to handle out-of-range insertions on flat_segment_tree

Another api version -> rename to mdds-1_2

myspell-dictionaries was updated to 20190423:
Serbian dictionary updated

Update af_ZA hunspell

Update Spanish dictionary

Update Slovenian dictionary

Update Breton dictionary

Update Galician dictionary");

  script_tag(name:"affected", value:"'LibreOffice' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1, SUSE Linux Enterprise Workstation Extension 15, SUSE Linux Enterprise Workstation Extension 15-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"myspell-de", rpm:"myspell-de~20190423~3.9.7", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-de_DE", rpm:"myspell-de_DE~20190423~3.9.7", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-dictionaries", rpm:"myspell-dictionaries~20190423~3.9.7", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-en", rpm:"myspell-en~20190423~3.9.7", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-en_US", rpm:"myspell-en_US~20190423~3.9.7", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-es", rpm:"myspell-es~20190423~3.9.7", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-es_ES", rpm:"myspell-es_ES~20190423~3.9.7", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-hu_HU", rpm:"myspell-hu_HU~20190423~3.9.7", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-lightproof-en", rpm:"myspell-lightproof-en~20190423~3.9.7", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-lightproof-hu_HU", rpm:"myspell-lightproof-hu_HU~20190423~3.9.7", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-lightproof-pt_BR", rpm:"myspell-lightproof-pt_BR~20190423~3.9.7", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-lightproof-ru_RU", rpm:"myspell-lightproof-ru_RU~20190423~3.9.7", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-nb_NO", rpm:"myspell-nb_NO~20190423~3.9.7", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-no", rpm:"myspell-no~20190423~3.9.7", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-pt_BR", rpm:"myspell-pt_BR~20190423~3.9.7", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ro", rpm:"myspell-ro~20190423~3.9.7", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ro_RO", rpm:"myspell-ro_RO~20190423~3.9.7", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ru_RU", rpm:"myspell-ru_RU~20190423~3.9.7", rls:"SLES15.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"myspell-de", rpm:"myspell-de~20190423~3.9.7", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-de_DE", rpm:"myspell-de_DE~20190423~3.9.7", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-dictionaries", rpm:"myspell-dictionaries~20190423~3.9.7", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-en", rpm:"myspell-en~20190423~3.9.7", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-en_US", rpm:"myspell-en_US~20190423~3.9.7", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-es", rpm:"myspell-es~20190423~3.9.7", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-es_ES", rpm:"myspell-es_ES~20190423~3.9.7", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-hu_HU", rpm:"myspell-hu_HU~20190423~3.9.7", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-lightproof-en", rpm:"myspell-lightproof-en~20190423~3.9.7", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-lightproof-hu_HU", rpm:"myspell-lightproof-hu_HU~20190423~3.9.7", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-lightproof-pt_BR", rpm:"myspell-lightproof-pt_BR~20190423~3.9.7", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-lightproof-ru_RU", rpm:"myspell-lightproof-ru_RU~20190423~3.9.7", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-nb_NO", rpm:"myspell-nb_NO~20190423~3.9.7", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-no", rpm:"myspell-no~20190423~3.9.7", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-pt_BR", rpm:"myspell-pt_BR~20190423~3.9.7", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ro", rpm:"myspell-ro~20190423~3.9.7", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ro_RO", rpm:"myspell-ro_RO~20190423~3.9.7", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ru_RU", rpm:"myspell-ru_RU~20190423~3.9.7", rls:"SLES15.0SP1"))) {
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
