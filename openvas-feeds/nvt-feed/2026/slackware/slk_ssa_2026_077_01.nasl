# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2026.077.01");
  script_cve_id("CVE-2026-32776", "CVE-2026-32777", "CVE-2026-32778");
  script_tag(name:"creation_date", value:"2026-03-19 04:40:15 +0000 (Thu, 19 Mar 2026)");
  script_version("2026-03-19T05:56:32+0000");
  script_tag(name:"last_modification", value:"2026-03-19 05:56:32 +0000 (Thu, 19 Mar 2026)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-17 15:52:53 +0000 (Tue, 17 Mar 2026)");

  script_name("Slackware: Security Advisory (SSA:2026-077-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2026-077-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2026&m=slackware-security.402987");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-32776");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-32777");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-32778");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'expat' package(s) announced via the SSA:2026-077-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New expat packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/expat-2.7.5-i586-1_slack15.0.txz: Upgraded.
 This update fixes security issues:
 Fix NULL function pointer dereference for empty external parameter entities,
 it takes use of both functions XML_ExternalEntityParserCreate and
 XML_SetParamEntityParsing for an application to be vulnerable.
 Protect from XML_TOK_INSTANCE_START infinite loop in function
 entityValueProcessor, it takes use of both functions
 XML_ExternalEntityParserCreate and XML_SetParamEntityParsing for an
 application to be vulnerable.
 Fix NULL dereference in function setContext on retry after an earlier
 ouf-of-memory condition, it takes use of function XML_ParserCreateNS or
 XML_ParserCreate_MM for an application to be vulnerable.
 For more information, see:
 [links moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'expat' package(s) on Slackware 15.0, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

release = slk_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLK15.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"expat", ver:"2.7.5-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"expat", ver:"2.7.5-x86_64-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLKcurrent") {

  if(!isnull(res = isslkpkgvuln(pkg:"expat", ver:"2.7.5-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"expat", ver:"2.7.5-x86_64-1", rls:"SLKcurrent"))) {
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
