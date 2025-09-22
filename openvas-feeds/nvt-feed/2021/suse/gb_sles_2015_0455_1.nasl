# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0455.1");
  script_cve_id("CVE-2014-2240", "CVE-2014-9656", "CVE-2014-9657", "CVE-2014-9658", "CVE-2014-9659", "CVE-2014-9660", "CVE-2014-9661", "CVE-2014-9662", "CVE-2014-9663", "CVE-2014-9664", "CVE-2014-9665", "CVE-2014-9666", "CVE-2014-9667", "CVE-2014-9668", "CVE-2014-9669", "CVE-2014-9670", "CVE-2014-9671", "CVE-2014-9672", "CVE-2014-9673", "CVE-2014-9674", "CVE-2014-9675");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0455-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0455-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150455-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916847");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916856");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916857");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916859");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916860");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916862");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916864");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916865");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916867");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916868");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916870");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916872");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916873");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916874");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916879");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916881");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-March/001274.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freetype2' package(s) announced via the SUSE-SU-2015:0455-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"freetype2 was updated to fix 20 security issues.

These security issues were fixed:
- CVE-2014-9663: The tt_cmap4_validate function in sfnt/ttcmap.c in FreeType before 2.5.4 validates a certain length field before that field's value is completely calculated, which allowed remote attackers to cause a denial of service (out-of-bounds read) or possibly have unspecified other impact via a crafted cmap SFNT table (bnc#916865).
- CVE-2014-9662: cff/cf2ft.c in FreeType before 2.5.4 did not validate the return values of point-allocation functions, which allowed remote attackers to cause a denial of service (heap-based buffer overflow) or possibly have unspecified other impact via a crafted OTF font (bnc#916860).
- CVE-2014-9661: type42/t42parse.c in FreeType before 2.5.4 did not consider that scanning can be incomplete without triggering an error, which allowed remote attackers to cause a denial of service (use-after-free) or possibly have unspecified other impact via a crafted Type42 font (bnc#916859).
- CVE-2014-9660: The _bdf_parse_glyphs function in bdf/bdflib.c in FreeType before 2.5.4 did not properly handle a missing ENDCHAR record, which allowed remote attackers to cause a denial of service (NULL pointer dereference) or possibly have unspecified other impact via a crafted BDF font (bnc#916858).
- CVE-2014-9667: sfnt/ttload.c in FreeType before 2.5.4 proceeds with offset+length calculations without restricting the values, which allowed remote attackers to cause a denial of service (integer overflow and out-of-bounds read) or possibly have unspecified other impact via a crafted SFNT table (bnc#916861).
- CVE-2014-9666: The tt_sbit_decoder_init function in sfnt/ttsbit.c in FreeType before 2.5.4 proceeds with a count-to-size association without restricting the count value, which allowed remote attackers to cause a denial of service (integer overflow and out-of-bounds read) or possibly have unspecified other impact via a crafted embedded bitmap (bnc#916862).
- CVE-2014-9665: The Load_SBit_Png function in sfnt/pngshim.c in FreeType before 2.5.4 did not restrict the rows and pitch values of PNG data, which allowed remote attackers to cause a denial of service (integer overflow and heap-based buffer overflow) or possibly have unspecified other impact by embedding a PNG file in a .ttf font file (bnc#916863).
- CVE-2014-9664: FreeType before 2.5.4 did not check for the end of the data during certain parsing actions, which allowed remote attackers to cause a denial of service (out-of-bounds read) or possibly have unspecified other impact via a crafted Type42 font, related to type42/t42parse.c and type1/t1load.c (bnc#916864).
- CVE-2014-9669: Multiple integer overflows in sfnt/ttcmap.c in FreeType before 2.5.4 allowed remote attackers to cause a denial of service (out-of-bounds read or memory corruption) or possibly have unspecified other impact via a crafted cmap SFNT table ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'freetype2' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"ft2demos", rpm:"ft2demos~2.5.3~5.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6", rpm:"libfreetype6~2.5.3~5.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6-32bit", rpm:"libfreetype6-32bit~2.5.3~5.1", rls:"SLES12.0"))) {
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
