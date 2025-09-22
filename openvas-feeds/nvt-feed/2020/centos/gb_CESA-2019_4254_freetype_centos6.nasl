# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.883148");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2015-9381", "CVE-2015-9382");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-10 03:15:00 +0000 (Tue, 10 Sep 2019)");
  script_tag(name:"creation_date", value:"2020-01-08 11:14:45 +0000 (Wed, 08 Jan 2020)");
  script_name("CentOS Update for freetype CESA-2019:4254 centos6");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");

  script_xref(name:"CESA", value:"2019:4254");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2019-December/035581.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freetype'
  package(s) announced via the CESA-2019:4254 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"FreeType is a free, high-quality, portable font engine that can open and
manage font files. FreeType loads, hints, and renders individual glyphs
efficiently.

Security Fix(es):

  * freetype: a heap-based buffer over-read in T1_Get_Private_Dict in
type1/t1parse.c leading to information disclosure (CVE-2015-9381)

  * freetype: mishandling ps_parser_skip_PS_token in an FT_New_Memory_Face
operation in skip_comment, psaux/psobjs.c, leads to a buffer over-read
(CVE-2015-9382)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'freetype' package(s) on CentOS 6.");

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

if(release == "CentOS6") {

  if(!isnull(res = isrpmvuln(pkg:"freetype", rpm:"freetype~2.3.11~19.el6_10", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype-demos", rpm:"freetype-demos~2.3.11~19.el6_10", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype-devel", rpm:"freetype-devel~2.3.11~19.el6_10", rls:"CentOS6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
