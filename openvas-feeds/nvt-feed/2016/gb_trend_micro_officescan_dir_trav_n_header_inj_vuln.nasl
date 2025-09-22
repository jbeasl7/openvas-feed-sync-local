# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:trend_micro:office_scan";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809141");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-1223");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-12 21:30:00 +0000 (Thu, 12 Aug 2021)");
  script_tag(name:"creation_date", value:"2016-08-22 15:40:21 +0530 (Mon, 22 Aug 2016)");
  script_name("Trend Micro OfficeScan Path Traversal and HTTP Header Injection Vulnerability");

  script_tag(name:"summary", value:"Trend Micro OfficeScan is prone to a path traversal and HTTP header injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to unintended file access
  and potential script execution.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause path traversal and HTTP header injection vulnerabilities.");

  script_tag(name:"affected", value:"Trend Micro OfficeScan versions prior to 11.0.6077.");

  script_tag(name:"solution", value:"Upgrade to  OfficeScan Corp. 11.0 Service Pack 1
  Critical Patch build 6077.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://esupport.trendmicro.com/solution/ja-JP/1114102.aspx");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91288");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_trend_micro_office_scan_detect.nasl");
  script_mandatory_keys("Trend/Micro/Officescan/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!trendVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(trendVer =~ "^11\.")
{
  if(version_is_less(version:trendVer, test_version:"11.0.6077"))
  {
    report = report_fixed_ver(installed_version:trendVer, fixed_version:"11.0.6077");
    security_message(data:report);
    exit(0);
  }
}
