# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2907.1");
  script_cve_id("CVE-2017-18267", "CVE-2018-13988", "CVE-2018-16646", "CVE-2018-18897", "CVE-2018-19058", "CVE-2018-19059", "CVE-2018-19060", "CVE-2018-19149", "CVE-2018-20481", "CVE-2018-20650", "CVE-2018-21009", "CVE-2019-12293", "CVE-2019-7310", "CVE-2022-27337");
  script_tag(name:"creation_date", value:"2023-07-21 04:33:21 +0000 (Fri, 21 Jul 2023)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-23 17:07:43 +0000 (Thu, 23 May 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2907-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2907-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232907-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1092945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102531");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107597");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114966");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115187");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115626");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120939");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124150");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199272");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2023-July/030446.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler' package(s) announced via the SUSE-SU-2023:2907-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for poppler fixes the following issues:

 - CVE-2022-27337: Fixed a logic error in the Hints::Hints function which can cause denial of service (bsc#1199272).
 - CVE-2018-21009: Fixed integer overflow in Parser:makeStream in Parser.cc (bsc#1149635).
 - CVE-2019-12293: Fixed heap-based buffer over-read in JPXStream:init in JPEG2000Stream.cc (bsc#1136105).
 - CVE-2018-20481: Fixed memory leak in GfxColorSpace:setDisplayProfile in GfxState.cc (bsc#1114966).
 - CVE-2019-7310: Fixed a heap-based buffer over-read allows remote attackers to cause DOS via a special crafted PDF (bsc#1124150).
 - CVE-2018-13988: Fixed buffer overflow in pdfunite (bsc#1102531).
 - CVE-2018-16646: Fixed infinite recursion in poppler/Parser.cc:Parser::getObj() function (bsc#1107597).
 - CVE-2018-19058: Fixed reachable abort in Object.h leading to denial of service (bsc#1115187).
 - CVE-2018-19059: Fixed out-of-bounds read in EmbFile:save2 in FileSpec.cc leading to denial of service (bsc#1115186).
 - CVE-2018-19060: Fixed NULL pointer dereference in goo/GooString.h leading to denial of service (bsc#1115185).
 - CVE-2018-19149: Fixed NULL pointer dereference in _poppler_attachment_new when called from poppler_annot_file_attachment_get_attachment (bsc#1115626).
 - CVE-2017-18267: Fixed denial of service (infinite recursion) via a crafted PDF file (bsc#1092945).
 - CVE-2018-20650: Fixed issue where a reachable Object in dictLookup assertion allows attackers to cause DOS (bsc#1120939).");

  script_tag(name:"affected", value:"'poppler' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8", rpm:"libpoppler-glib8~0.43.0~16.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt4-4", rpm:"libpoppler-qt4-4~0.43.0~16.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler60", rpm:"libpoppler60~0.43.0~16.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-tools", rpm:"poppler-tools~0.43.0~16.25.1", rls:"SLES12.0SP5"))) {
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
