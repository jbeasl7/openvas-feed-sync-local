# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815451");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2019-11746", "CVE-2019-11744", "CVE-2019-11742", "CVE-2019-11753",
                "CVE-2019-11752", "CVE-2019-9812", "CVE-2019-11743", "CVE-2019-11740");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-13 19:51:00 +0000 (Mon, 13 Jan 2020)");
  script_tag(name:"creation_date", value:"2019-09-05 11:28:56 +0530 (Thu, 05 Sep 2019)");
  script_name("Mozilla Firefox ESR Security Advisories - 1 - (MFSA2019-25, MFSA2019-27) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple use-after-free errors.

  - A same-origin policy violation.

  - Privilege escalation with Mozilla Maintenance Service in custom Firefox
    installation location.

  - Sandbox escape through Firefox Sync.

  - Navigation events were not fully adhering to the W3C's 'Navigation-Timing Level 2'
    draft specification in some instances for the unload event.

  - Some HTML elements, such as <title> and <textarea>, can contain literal angle
    brackets without treating them as markup.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to
  cause denial of service, escalate privileges, conduct cross site scripting
  attacks and disclose sensitive information.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before
  60.9 on Windows.");

  script_tag(name:"solution", value:"Update to Mozilla Firefox ESR version 60.9
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-27/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl", "gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"60.9")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"60.9", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
