# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.819993");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2022-22753", "CVE-2022-22754", "CVE-2022-22755", "CVE-2022-22756",
                "CVE-2022-22757", "CVE-2022-22759", "CVE-2022-22760", "CVE-2022-22761",
                "CVE-2022-22764", "CVE-2022-0511");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-29 22:51:00 +0000 (Thu, 29 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-02-10 09:38:39 +0530 (Thu, 10 Feb 2022)");
  script_name("Mozilla Firefox Security Advisories (MFSA2022-04, MFSA2022-05) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Privilege Escalation to SYSTEM on Windows via Maintenance Service.

  - Extensions could have bypassed permission confirmation during update.

  - XSL could have allowed JavaScript execution after a tab was closed.

  - Drag and dropping an image could have resulted in the dropped object being an executable.

  - Remote Agent did not prevent local websites from connecting.

  - Sandboxed iframes could have executed script if the parent appended elements.

  - Cross-Origin responses could be distinguished between script and non-script content-types.

  - frame-ancestors Content Security Policy directive was not enforced for framed extension pages.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  escalate privileges, bypass permissions and conduct javascript execution.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  97 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 97
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-04/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
ffVer = infos["version"];
ffPath = infos["location"];

if(version_is_less(version:ffVer, test_version:"97"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"97", install_path:ffPath);
  security_message(data:report);
  exit(0);
}
