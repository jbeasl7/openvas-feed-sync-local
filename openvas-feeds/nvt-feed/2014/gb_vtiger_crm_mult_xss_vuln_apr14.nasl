# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vtiger:vtiger_crm";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804541");
  script_version("2024-03-04T14:37:58+0000");
  script_cve_id("CVE-2013-7326");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2014-04-17 17:45:25 +0530 (Thu, 17 Apr 2014)");

  script_name("Vtiger 'return_url' Parameter Multiple Cross Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"Vtiger CRM is prone to multiple XSS vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaws are due to improper sanitation of user supplied input passed via
'return_url' parameter to savetemplate.php and unspecified vectors to deletetask.php, edittask.php, savetask.php,
or saveworkflow.php.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Vtiger CRM version 5.4.0");

  script_tag(name:"solution", value:"Upgrade to the latest version of Vtiger 6.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/89662");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64236");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Dec/51");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124402");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_vtiger_crm_detect.nasl");
  script_mandatory_keys("vtiger/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_equal(version:version, test_version:"5.4.0")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"6.0.0");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
