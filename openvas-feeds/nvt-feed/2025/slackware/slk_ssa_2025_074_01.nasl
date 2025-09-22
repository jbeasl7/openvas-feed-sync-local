# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2025.074.01");
  script_cve_id("CVE-2025-27363");
  script_tag(name:"creation_date", value:"2025-03-17 15:24:03 +0000 (Mon, 17 Mar 2025)");
  script_version("2025-05-08T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-05-08 05:40:19 +0000 (Thu, 08 May 2025)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-07 16:00:55 +0000 (Wed, 07 May 2025)");

  script_name("Slackware: Security Advisory (SSA:2025-074-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK15\.0");

  script_xref(name:"Advisory-ID", value:"SSA:2025-074-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2025&m=slackware-security.350360");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freetype' package(s) announced via the SSA:2025-074-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New freetype packages are available for Slackware 15.0 to fix a security issue.


Here are the details from the Slackware 15.0 ChangeLog:
patches/packages/freetype-2.13.3-i586-1_slack15.0.txz: Upgraded.
 This update fixes bugs and a security issue:
 An out of bounds write exists in FreeType versions 2.13.0 and below (newer
 versions of FreeType are not vulnerable) when attempting to parse font
 subglyph structures related to TrueType GX and variable font files. The
 vulnerable code assigns a signed short value to an unsigned long and then
 adds a static value causing it to wrap around and allocate too small of a
 heap buffer. The code then writes up to 6 signed long integers out of bounds
 relative to this buffer. This may result in arbitrary code execution.
 This vulnerability may have been exploited in the wild.
 For more information, see:
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'freetype' package(s) on Slackware 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isslkpkgvuln(pkg:"freetype", ver:"2.13.3-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"freetype", ver:"2.13.3-x86_64-1_slack15.0", rls:"SLK15.0"))) {
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
