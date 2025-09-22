# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:trend_micro:office_scan";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813615");
  script_version("2023-07-20T05:05:18+0000");
  script_cve_id("CVE-2018-10358", "CVE-2018-10359", "CVE-2018-10505", "CVE-2018-10506",
                "CVE-2018-10507", "CVE-2018-10508", "CVE-2018-10509");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-06-26 10:57:13 +0530 (Tue, 26 Jun 2018)");
  script_name("Trend Micro OfficeScan Multiple Vulnerabilities (1119961)");

  script_tag(name:"summary", value:"Trend Micro OfficeScan is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The lack of proper validation of the length of user-supplied data prior to
    using that length to initialize a pool-based buffer within the processing of
    IOCTL 0x2200B4, IOCTL 0x2200B4, IOCTL 0x220008 in the TMWFP driver.

  - An out-of-bounds read error within processing of IOCTL 0x220004 by the tmwfp
    driver.

  - A vulnerability that render the OfficeScan Unauthorized Change Prevention
    inoperable on vulnerable installations.

  - A URL vulnerability to elevate account permissions on vulnerable installations.

  - An OfficeScan Browser Refresh vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to disclose sensitive information, escalate privileges and to bypass other
  security restrictions on vulnerable installations of Trend Micro OfficeScan.");

  script_tag(name:"affected", value:"Trend Micro OfficeScan versions XG SP1
  prior to XG SP1 CP 5147, XG (GM Version) prior to XG CP 1876 (Pre-SP1), 11.0
  SP1 prior to 11.0 SP1 CP 6540.");

  script_tag(name:"solution", value:"Upgrade to OfficeScan XG SP1 CP 5147 or
  XG CP 1876 (Pre-SP1) or 110.0 SP1 CP 6540 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://success.trendmicro.com/solution/1119961");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("gb_trend_micro_office_scan_detect.nasl");
  script_mandatory_keys("Trend/Micro/Officescan/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^1[12]\.") {

  ## http://docs.trendmicro.com/all/ent/officescan/v11.0/en-us/osce_11.0_sp1_server_readme.htm#7 - 11.0 SP1 =  11.0.2995
  ## http://files.trendmicro.com/products/officescan/11.0_SP1/osce_11_sp1_patch1_win_en_criticalpatch_6540.html - 110.0 SP1 CP 6540 = 11.0.6540
  if(version_in_range(version:vers, test_version:"11.0.2995", test_version2:"11.0.6539")) {
    fix = "110.0 SP1 CP 6540";
  }

  ## http://files.trendmicro.com/products/officescan/XG/SP1/osce_xg_sp1_win_en_criticalpatch_b4406.html - XG SP1 = 12.0.4345
  ## http://files.trendmicro.com/products/officescan/XG/SP1/osce_xg_sp1_win_en_criticalpatch_5147.html - XG SP1 CP 5147 = 12.0.5147
  else if(version_in_range(version:vers, test_version:"12.0.4345", test_version2:"12.0.5146")) {
    fix = "XG SP1 CP 5147";
  }

  ## http://files.trendmicro.com/products/officescan/XG/patch1/osce_xg_win_en_criticalpatch_1876.html - XG CP 1876 (Pre-SP1) = 12.0.1876
  ## http://docs.trendmicro.com/all/ent/officescan/v12.0/en-us/osce_12.0_server_readme.htm#7 XG (GM Version) = 12.0.1315
  else if(version_in_range(version:vers, test_version:"12.0.1315", test_version2:"12.0.1875")) {
    fix = "XG CP 1876 (Pre-SP1)";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
