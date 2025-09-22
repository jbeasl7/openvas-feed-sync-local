# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0462.1");
  script_cve_id("CVE-2016-10244", "CVE-2017-8105", "CVE-2017-8287");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:48 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-09 12:44:24 +0000 (Tue, 09 May 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0462-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0462-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180462-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028103");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035807");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036457");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-February/003736.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freetype2' package(s) announced via the SUSE-SU-2018:0462-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for freetype2 fixes the following issues:

Security issue fixed:
- CVE-2016-10244: The parse_charstrings function in type1/t1load.c did not
 ensure that a font contains a glyph name, which allowed remote attackers
 to cause a denial of service (heap-based buffer over-read) or possibly
 have unspecified other impact via a crafted file (bsc#1028103).

- CVE-2017-8105: Fixed an out-of-bounds write caused by a heap-based
 buffer overflow related to the t1_decoder_parse_charstrings function in
 psaux/t1decode.ca (bsc#1035807)
- CVE-2017-8287: an out-of-bounds write caused by a heap-based buffer
 overflow related to the t1_builder_close_contour function in psaux/psobjs.c
 (bsc#1036457)");

  script_tag(name:"affected", value:"'freetype2' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"freetype2", rpm:"freetype2~2.3.7~25.45.5.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype2-32bit", rpm:"freetype2-32bit~2.3.7~25.45.5.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype2-x86", rpm:"freetype2-x86~2.3.7~25.45.5.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ft2demos", rpm:"ft2demos~2.3.7~25.45.5.1", rls:"SLES11.0SP4"))) {
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
