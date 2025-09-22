# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800475");
  script_version("2024-02-08T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-02-19 11:58:13 +0100 (Fri, 19 Feb 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-0186", "CVE-2010-0187");
  script_name("Adobe Flash Player/Air Multiple Vulnerabilities (Feb 2010) - Windows");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=563819");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38198");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38200");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-06.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass security
  restrictions.");

  script_tag(name:"affected", value:"Adobe AIR version prior to 1.5.3.9130

  Adobe Flash Player 10 version prior to 10.0.45.2 on Windows");

  script_tag(name:"insight", value:"Cross domain vulnerabilities present in Adobe Flash Player/Adobe Air allows
  remote attackers to bypass intended sandbox restrictions and make cross-domain requests via unspecified vectors.");

  script_tag(name:"solution", value:"Update to Adobe Air 1.5.3.9130 or Adobe Flash Player 10.0.45.2.");

  script_tag(name:"summary", value:"Adobe Flash Player/Air is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:adobe:flash_player",
                     "cpe:/a:adobe:adobe_air");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];
cpe  = infos["cpe"];

if(cpe == "cpe:/a:adobe:flash_player") {
  if(version_in_range(version:vers, test_version:"10.0", test_version2:"10.0.45.1")) {
    report = report_fixed_ver(installed_version:vers, vulnerable_range:"10.0 - 10.0.45.1", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
} else if(cpe == "cpe:/a:adobe:adobe_air") {
  if(version_is_less(version:vers, test_version:"1.5.3.9130")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"1.5.3.9130", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
