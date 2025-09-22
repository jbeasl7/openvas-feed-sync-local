# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mcafee:epolicy_orchestrator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809026");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2015-8765");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-14 19:21:00 +0000 (Thu, 14 Feb 2019)");
  script_tag(name:"creation_date", value:"2016-09-01 10:20:57 +0530 (Thu, 01 Sep 2016)");
  script_name("McAfee ePolicy Orchestrator Arbitrary Code Execution Vulnerability (Sep 2016)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mcafee_epolicy_orchestrator_detect.nasl");
  script_mandatory_keys("mcafee_ePO/installed");

  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/576313");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/85696");

  script_tag(name:"summary", value:"McAfee ePolicy Orchestrator is prone to an arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an insecure deserialization of data
  in apache commons collections.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers
  to execute arbitrary code.");

  script_tag(name:"affected", value:"McAfee ePolicy Orchestrator version 4.6.x through
  4.6.9, 5.0.x, 5.1.x before 5.1.3 Hotfix 1106041 and 5.3.x before 5.3.1 Hotfix 1106041");

  script_tag(name:"solution", value:"Apply the hotfix 5.1.3 Hotfix 1106041 and
  5.3.1 Hotfix 1106041.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!mcaPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!mcaVer = get_app_version(cpe:CPE, port:mcaPort)){
  exit(0);
}

if(version_in_range(version:mcaVer, test_version:"4.6.0", test_version2:"4.6.9") ||
   version_in_range(version:mcaVer, test_version:"5.0.0", test_version2:"5.1.3") ||
   version_in_range(version:mcaVer, test_version:"5.3.0", test_version2:"5.3.1")){
  report = report_fixed_ver(installed_version:mcaVer, fixed_version:"Apply the appropriate Hotfix");
  security_message(data:report, port:mcaPort);
  exit(0);
}

exit(99);
