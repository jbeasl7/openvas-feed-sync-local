# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:adobe_air";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806684");
  script_version("2024-02-09T05:06:25+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-0964", "CVE-2016-0965", "CVE-2016-0966", "CVE-2016-0967",
                "CVE-2016-0968", "CVE-2016-0969", "CVE-2016-0970", "CVE-2016-0971",
                "CVE-2016-0972", "CVE-2016-0973", "CVE-2016-0974", "CVE-2016-0975",
                "CVE-2016-0976", "CVE-2016-0977", "CVE-2016-0978", "CVE-2016-0979",
                "CVE-2016-0980", "CVE-2016-0981", "CVE-2016-0982", "CVE-2016-0983",
                "CVE-2016-0984", "CVE-2016-0985");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-26 21:42:00 +0000 (Thu, 26 Jan 2023)");
  script_tag(name:"creation_date", value:"2016-02-12 17:36:12 +0530 (Fri, 12 Feb 2016)");
  script_name("Adobe Air Multiple Vulnerabilities (Feb 2016) - Windows");

  script_tag(name:"summary", value:"Adobe Air is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The Multiple memory corruption errors.

  - The Multiple use-after-free errors.

  - A heap buffer overflow error.

  - A type confusion error.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"Adobe Air version before 20.0.0.260 on
  Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Air version 20.0.0.260 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-04.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("Adobe/Air/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"20.0.0.260")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"20.0.0.260");
  security_message(data:report);
  exit(0);
}
