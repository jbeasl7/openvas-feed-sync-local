# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1784.1");
  script_cve_id("CVE-2014-9805", "CVE-2014-9806", "CVE-2014-9807", "CVE-2014-9808", "CVE-2014-9809", "CVE-2014-9810", "CVE-2014-9811", "CVE-2014-9812", "CVE-2014-9813", "CVE-2014-9814", "CVE-2014-9815", "CVE-2014-9816", "CVE-2014-9817", "CVE-2014-9818", "CVE-2014-9819", "CVE-2014-9820", "CVE-2014-9821", "CVE-2014-9822", "CVE-2014-9823", "CVE-2014-9824", "CVE-2014-9825", "CVE-2014-9826", "CVE-2014-9828", "CVE-2014-9829", "CVE-2014-9830", "CVE-2014-9831", "CVE-2014-9832", "CVE-2014-9833", "CVE-2014-9834", "CVE-2014-9835", "CVE-2014-9836", "CVE-2014-9837", "CVE-2014-9838", "CVE-2014-9839", "CVE-2014-9840", "CVE-2014-9841", "CVE-2014-9842", "CVE-2014-9843", "CVE-2014-9844", "CVE-2014-9845", "CVE-2014-9846", "CVE-2014-9847", "CVE-2014-9848", "CVE-2014-9849", "CVE-2014-9850", "CVE-2014-9851", "CVE-2014-9852", "CVE-2014-9853", "CVE-2014-9854", "CVE-2015-8894", "CVE-2015-8895", "CVE-2015-8896", "CVE-2015-8897", "CVE-2015-8898", "CVE-2015-8900", "CVE-2015-8901", "CVE-2015-8902", "CVE-2015-8903", "CVE-2016-4562", "CVE-2016-4563", "CVE-2016-4564", "CVE-2016-5687", "CVE-2016-5688", "CVE-2016-5689", "CVE-2016-5690", "CVE-2016-5691", "CVE-2016-5841", "CVE-2016-5842");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-15 03:02:17 +0000 (Thu, 15 Dec 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1784-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1784-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161784-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983234");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983253");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983259");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983292");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983305");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983308");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983521");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983523");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983533");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983752");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983774");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983794");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983799");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984014");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984023");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984028");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984135");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984137");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984142");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984144");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984149");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984150");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984160");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984166");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984181");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984184");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984187");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984370");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984372");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984373");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984375");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984379");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984394");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984398");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984406");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984408");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984409");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984433");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984436");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/985442");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/985448");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/985451");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/985456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/985460");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986608");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986609");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-July/002153.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2016:1784-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ImageMagick was updated to fix 66 security issues.

These security issues were fixed:
- CVE-2014-9810: SEGV in dpx file handler. (bsc#983803).
- CVE-2014-9811: Crash in xwd file handler (bsc#984032).
- CVE-2014-9812: NULL pointer dereference in ps file handling (bsc#984137).
- CVE-2014-9813: Crash on corrupted viff file (bsc#984035).
- CVE-2014-9814: NULL pointer dereference in wpg file handling (bsc#984193).
- CVE-2014-9815: Crash on corrupted wpg file (bsc#984372).
- CVE-2014-9816: Out of bound access in viff image (bsc#984398).
- CVE-2014-9817: Heap buffer overflow in pdb file handling (bsc#984400).
- CVE-2014-9818: Out of bound access on malformed sun file (bsc#984181).
- CVE-2014-9819: Heap overflow in palm files (bsc#984142).
- CVE-2014-9830: Handling of corrupted sun file (bsc#984135).
- CVE-2014-9831: Handling of corrupted wpg file (bsc#984375).
- CVE-2014-9850: Incorrect thread limit logic (bsc#984149).
- CVE-2014-9851: Crash when parsing resource block (bsc#984160).
- CVE-2014-9852: Incorrect usage of object after it has been destroyed (bsc#984191).
- CVE-2014-9853: Memory leak in rle file handling (bsc#984408).
- CVE-2015-8902: PDB file DoS (CPU consumption) (bsc#983253).
- CVE-2015-8903: Denial of service (cpu) in vicar (bsc#983259).
- CVE-2015-8900: HDR file DoS (endless loop) (bsc#983232).
- CVE-2015-8901: MIFF file DoS (endless loop) (bsc#983234).
- CVE-2016-5688: Various invalid memory reads in ImageMagick WPG (bsc#985442).
- CVE-2014-9834: Heap overflow in pict file (bsc#984436).
- CVE-2014-9806: Prevent leak of file descriptor due to corrupted file. (bsc#983774).
- CVE-2016-5687: Out of bounds read in DDS coder (bsc#985448).
- CVE-2014-9838: Out of memory crash in magick/cache.c (bsc#984370).
- CVE-2014-9854: Filling memory during identification of TIFF image (bsc#984184).
- CVE-2015-8898: Prevent null pointer access in magick/constitute.c (bsc#983746).
- CVE-2014-9833: Heap overflow in psd file (bsc#984406).
- CVE-2015-8894: Double free in coders/tga.c:221 (bsc#983523).
- CVE-2015-8895: Integer and Buffer overflow in coders/icon.c (bsc#983527).
- CVE-2015-8896: Double free / integer truncation issue in coders/pict.c:2000 (bsc#983533).
- CVE-2015-8897: Out of bounds error in SpliceImage (bsc#983739).
- CVE-2016-5690: Bad foor loop in DCM coder (bsc#985451).
- CVE-2016-5691: Checks for pixel.red/green/blue in dcm coder (bsc#985456).
- CVE-2014-9836: Crash in xpm file handling (bsc#984023).
- CVE-2014-9808: SEGV due to corrupted dpc images. (bsc#983796).
- CVE-2014-9821: Avoid heap overflow in pnm files. (bsc#984014).
- CVE-2014-9820: Heap overflow in xpm files (bsc#984150).
- CVE-2014-9823: Heap overflow in palm file (bsc#984401).
- CVE-2014-9822: Heap overflow in quantum file (bsc#984187).
- CVE-2014-9825: Heap overflow in corrupted psd file (bsc#984427).
- CVE-2014-9824: Heap overflow in psd file (bsc#984185).
- CVE-2014-9809: SEGV due to corrupted xwd ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ImageMagick' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~30.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~30.2", rls:"SLES12.0SP1"))) {
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
