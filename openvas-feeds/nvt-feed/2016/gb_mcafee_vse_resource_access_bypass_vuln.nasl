# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mcafee:virusscan_enterprise";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809974");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-3984");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-18 21:28:00 +0000 (Wed, 18 May 2016)");
  script_tag(name:"creation_date", value:"2016-05-10 14:30:14 +0530 (Tue, 10 May 2016)");
  script_name("McAfee VirusScan Enterprise Resource Access Bypass Vulnerability");

  script_tag(name:"summary", value:"McAfee VirusScan Enterprise is prone to resource access bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the McAfee VirusScan
  Console (mcconsol.exe) does not properly check the password.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  Windows administrator to bypass the security restrictions and disable the
  antivirus engine without knowing the correct management password.");

  script_tag(name:"affected", value:"McAfee VirusScan Enterprise versions before
  8.8 Patch 7.");

  script_tag(name:"solution", value:"Upgrade to McAfee VirusScan Enterprise
  version 8.8 Patch 7 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10151");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_mcafee_virusscan_enterprise_detect_win.nasl");
  script_mandatory_keys("McAfee/VirusScan/Win/Ver");
  script_xref(name:"URL", value:"http://www.mcafee.com");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!mcafVer = get_app_version(cpe:CPE)){
  exit(0);
}

## https://kc.mcafee.com/resources/sites/MCAFEE/content/live/PRODUCT_DOCUMENTATION/26000/PD26382/en_US/vse_887_rn_0-00_en-us.pdf

if(version_is_less(version:mcafVer, test_version:"8.8.0.1528"))
{
  report = report_fixed_ver(installed_version:mcafVer, fixed_version:"8.8 patch 7(8.8.0.1528)");
  security_message(data:report);
  exit(0);
}

