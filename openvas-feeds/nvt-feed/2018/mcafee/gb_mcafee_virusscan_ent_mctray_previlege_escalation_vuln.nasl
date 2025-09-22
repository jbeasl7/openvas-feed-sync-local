# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mcafee:virusscan_enterprise";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813508");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2018-6674");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:P/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-06-05 14:03:19 +0530 (Tue, 05 Jun 2018)");
  script_name("McAfee VirusScan Enterprise 'McTray.exe' Privilege Escalation Vulnerability - Windows");

  script_tag(name:"summary", value:"McAfee VirusScan Enterprise is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the process McTray.exe
  running with elevated privileges.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to manipulate the system and then control of the physical machine.");

  script_tag(name:"affected", value:"McAfee VirusScan Enterprise 8.8 Patch 10
  and earlier on Windows.");

  script_tag(name:"solution", value:"Update to version 8.8 Patch 11 or later
  on Windows. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mcafee.com");
  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10237");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Privilege escalation");
  script_dependencies("gb_mcafee_virusscan_enterprise_detect_win.nasl");
  script_mandatory_keys("McAfee/VirusScan/Win/Ver");
  exit(0);

}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
mVer = infos["version"];
mPath = infos["location"];

# 8.8.0.1982 = 8.8 Patch 11 (https://kc.mcafee.com/resources/sites/MCAFEE/content/live/PRODUCT_DOCUMENTATION/27000/PD27441/en_US/vse_8811_rn_0-00_en-us.pdf)
if(mVer =~ "^8\.8\." && version_is_less(version:mVer, test_version:"8.8.0.1982"))
{
  report = report_fixed_ver(installed_version:mVer, fixed_version:"8.8 patch 11(8.8.0.1982)", install_path:mPath);
  security_message(data:report);
  exit(0);
}

exit(99);
