# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:tivoli_endpoint_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809396");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2013-0453");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-10-24 18:19:22 +0530 (Mon, 24 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("IBM Tivoli Endpoint Manager Cross Site Scripting Vulnerability (Oct 2016)");

  script_tag(name:"summary", value:"IBM Tivoli Endpoint Manager is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in web reports.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML.");

  script_tag(name:"affected", value:"IBM Tivoli Endpoint Manager versions
  before 8.2.1372.");

  script_tag(name:"solution", value:"Upgrade to IBM Tivoli Endpoint Manager
  version 8.2.1372, or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.ibm.com/blogs/psirt/security-bulletin-cross-site-scripting-xss-vulnerability-was-discovered-in-web-reports-cve-2013-0453/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58632");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ibm_endpoint_manager_web_detect.nasl");
  script_mandatory_keys("ibm_endpoint_manager/installed");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!tivPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!tivVer = get_app_version(cpe:CPE, port:tivPort)){
  exit(0);
}

if(version_is_less(version:tivVer, test_version:"8.2.1372"))
{
  report = report_fixed_ver(installed_version:tivVer, fixed_version:"8.2.1372");
  security_message(port:tivPort, data:report);
  exit(0);
}

