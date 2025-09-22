# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mcafee:epolicy_orchestrator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805594");
  script_version("2024-03-04T14:37:58+0000");
  script_cve_id("CVE-2015-4559");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-06-24 11:25:11 +0530 (Wed, 24 Jun 2015)");
  script_name("McAfee ePolicy Orchestrator Cross Site Scripting Vulnerability (Jun 2015)");

  script_tag(name:"summary", value:"McAfee ePolicy Orchestrator is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in the product
  deployment feature in the Java core web services.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to execute arbitrary HTML and script code in the context of an
  affected site.");

  script_tag(name:"affected", value:"McAfee ePolicy Orchestrator version 5.x
  before 5.1.2");

  script_tag(name:"solution", value:"Upgrade to McAfee ePolicy Orchestrator
  version 5.1.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10121");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mcafee_epolicy_orchestrator_detect.nasl");
  script_mandatory_keys("mcafee_ePO/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:version, test_version:"5.0.0", test_version2:"5.1.1")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"5.1.2");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
