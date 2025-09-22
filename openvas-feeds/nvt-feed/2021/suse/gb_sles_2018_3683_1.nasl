# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3683.1");
  script_cve_id("CVE-2018-10583");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:34 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-13 14:19:05 +0000 (Wed, 13 Jun 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3683-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3683-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183683-1/");
  script_xref(name:"URL", value:"https://wiki.documentfoundation.org/ReleaseNotes/6.1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libepubgen, liblangtag, libmwaw, libnumbertext, libreoffice, libstaroffice, libwps, myspell-dictionaries, xmlsec1' package(s) announced via the SUSE-SU-2018:3683-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for LibreOffice, libepubgen, liblangtag, libmwaw,
libnumbertext, libstaroffice, libwps, myspell-dictionaries, xmlsec1 fixes the following issues:

LibreOffice was updated to 6.1.3.2 (fate#326624) and contains new features and lots of bugfixes:

The full changelog can be found on:

 [link moved to references]

Bugfixes:
bsc#1095639 Exporting to PPTX results in vertical labels being shown
 horizontally

bsc#1098891 Table in PPTX misplaced and partly blue

bsc#1088263 Labels in chart change (from white and other colors) to
 black when saving as PPTX

bsc#1095601 Exporting to PPTX shifts arrow shapes quite a bit Add more translations:
 * Belarusian
 * Bodo
 * Dogri
 * Frisian
 * Gaelic
 * Paraguayan_Guaran
 * Upper_Sorbian
 * Konkani
 * Kashmiri
 * Luxembourgish
 * Monglolian
 * Manipuri
 * Burnese
 * Occitan
 * Kinyarwanda
 * Santali
 * Sanskrit
 * Sindhi
 * Sidamo
 * Tatar
 * Uzbek
 * Upper Sorbian
 * Venetian
 * Amharic
 * Asturian
 * Tibetian
 * Bosnian
 * English GB
 * English ZA
 * Indonesian
 * Icelandic
 * Georgian
 * Khmer
 * Lao
 * Macedonian
 * Nepali
 * Oromo
 * Albanian
 * Tajik
 * Uyghur
 * Vietnamese
 * Kurdish Try to build all languages see bsc#1096360

Make sure to install the KDE5/Qt5 UI/filepicker

Try to implement safeguarding to avoid bsc#1050305

Disable base-drivers-mysql as it needs mysqlcppcon that is only for
 mysql and not mariadb, causes issues bsc#1094779
 * Users can still connect using jdbc/odbc

Fix java detection on machines with too many cpus CVE-2018-10583: An information disclosure vulnerability occurred when
 LibreOffice automatically processed and initiated an SMB connection
 embedded in a malicious file, as demonstrated by
 xlink:href=file://192.168.0.2/test.jpg within an office:document-content
 element in a .odt XML document. (bsc#1091606)

libepubgen was updated to 0.1.1:
Avoid inside or .

Avoid writin vertical-align attribute without a value.

Fix generation of invalid XHTML when there is a link starting at the
 beginning of a footnote.

Handle relative width for images.

Fixed layout: write chapter names to improve navigation.

Support writing mode.

Start a new HTML file at every page span in addition to the splits
 induced by the chosen split method. This is to ensure that specified
 writing mode works correctly, as it is HTML attribute.

liblangtag was updated to 0.6.2:
use standard function

fix leak in test

libmwaw was updated to 0.3.14:
Support MS Multiplan 1.1 files

libnumbertext was update to 1.0.5:
Various fixes in numerical calculations and issues reported on
 libreoffice tracker

libstaroffice was updated to 0.0.6:
retrieve some StarMath's formula,

retrieve some charts as graphic,

retrieve some fields in sda/sdc/sdp text-boxes,

.sdw: retrieve more attachments.

libwps was updated to 0.4.9:
QuattroPro: add parser to .wb3 files

Multiplan: add parser to DOS v1-v3 files

charts: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'libepubgen, liblangtag, libmwaw, libnumbertext, libreoffice, libstaroffice, libwps, myspell-dictionaries, xmlsec1' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15, SUSE Linux Enterprise Module for Packagehub Subpackages 15, SUSE Linux Enterprise Workstation Extension 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"myspell-de", rpm:"myspell-de~20181025~3.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-de_DE", rpm:"myspell-de_DE~20181025~3.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-dictionaries", rpm:"myspell-dictionaries~20181025~3.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-en", rpm:"myspell-en~20181025~3.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-en_US", rpm:"myspell-en_US~20181025~3.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-es", rpm:"myspell-es~20181025~3.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-es_ES", rpm:"myspell-es_ES~20181025~3.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-hu_HU", rpm:"myspell-hu_HU~20181025~3.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-lightproof-en", rpm:"myspell-lightproof-en~20181025~3.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-lightproof-hu_HU", rpm:"myspell-lightproof-hu_HU~20181025~3.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-lightproof-pt_BR", rpm:"myspell-lightproof-pt_BR~20181025~3.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-lightproof-ru_RU", rpm:"myspell-lightproof-ru_RU~20181025~3.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-nb_NO", rpm:"myspell-nb_NO~20181025~3.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-no", rpm:"myspell-no~20181025~3.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-pt_BR", rpm:"myspell-pt_BR~20181025~3.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ro", rpm:"myspell-ro~20181025~3.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ro_RO", rpm:"myspell-ro_RO~20181025~3.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"myspell-ru_RU", rpm:"myspell-ru_RU~20181025~3.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmlsec1-gcrypt1", rpm:"libxmlsec1-gcrypt1~1.2.26~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmlsec1-gcrypt1-debuginfo", rpm:"libxmlsec1-gcrypt1-debuginfo~1.2.26~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmlsec1-gnutls1", rpm:"libxmlsec1-gnutls1~1.2.26~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmlsec1-gnutls1-debuginfo", rpm:"libxmlsec1-gnutls1-debuginfo~1.2.26~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmlsec1-openssl1", rpm:"libxmlsec1-openssl1~1.2.26~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxmlsec1-openssl1-debuginfo", rpm:"libxmlsec1-openssl1-debuginfo~1.2.26~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmlsec1-debuginfo", rpm:"xmlsec1-debuginfo~1.2.26~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmlsec1-debugsource", rpm:"xmlsec1-debugsource~1.2.26~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmlsec1-gnutls-devel", rpm:"xmlsec1-gnutls-devel~1.2.26~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmlsec1-openssl-devel", rpm:"xmlsec1-openssl-devel~1.2.26~3.3.1", rls:"SLES15.0"))) {
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
