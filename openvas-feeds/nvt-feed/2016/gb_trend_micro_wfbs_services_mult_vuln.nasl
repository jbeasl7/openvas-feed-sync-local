# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:trend_micro:business_security_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809153");
  script_version("2023-11-03T05:05:46+0000");
  script_cve_id("CVE-2016-1223", "CVE-2016-1224");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-09 17:11:00 +0000 (Thu, 09 Sep 2021)");
  script_tag(name:"creation_date", value:"2016-08-23 12:01:39 +0530 (Tue, 23 Aug 2016)");
  script_name("Trend Micro WFBS Services Multiple Vulnerabilities");
  script_tag(name:"summary", value:"Trend Micro Worry-Free Business Security Services is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to the unintended
  file could be accessed and potential unintended script may gets executed.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause path traversal and HTTP header injection Vulnerability and to inject
  arbitrary HTTP headers and conduct cross-site scripting (XSS).");

  script_tag(name:"affected", value:"Trend Micro Worry-Free Business Security
  Services versions 5.x through 5.9.1095.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://esupport.trendmicro.com/solution/ja-JP/1114102.aspx");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91288");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91290");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN48847535/index.html");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_trend_micro_wfbss_detect.nasl");
  script_mandatory_keys("Trend/Micro/Worry-Free/Business/Security/Services/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(vers =~ "^5\." && version_is_less_equal(version:vers, test_version:"5.9.1095")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See references");
  security_message(data:report);
  exit(0);
}

exit(99);
