# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:web_gateway";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805228");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2014-1651", "CVE-2014-1652");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-12-23 12:50:52 +0530 (Tue, 23 Dec 2014)");
  script_name("Symantec Web Gateway Multiple Vulnerabilities -02 (Dec 2014)");

  script_tag(name:"summary", value:"Symantec Web Gateway is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple errors are due to:

  - An error in the 'clientreport.php' script which do not properly sanitize
  user-supplied input before using it in SQL queries.

  - An error in program which do not validate input to multiple unspecified
  report parameters before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database
  allowing for the manipulation or disclosure of arbitrary data and execute
  arbitrary script code in a user's browser session within the trust
  relationship between their browser and the server.");

  script_tag(name:"affected", value:"Symantec Web Gateway prior to version
  5.2");

  script_tag(name:"solution", value:"Upgrade to Symantec Web Gateway version
  5.2 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1030443");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67754");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67755");
  script_xref(name:"URL", value:"http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2014&suid=20140616_00");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_dependencies("gb_symantec_web_gateway_detect.nasl");
  script_mandatory_keys("symantec_web_gateway/installed");
  script_xref(name:"URL", value:"http://www.symantec.com/web-gateway/");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!symPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!symVer = get_app_version(cpe:CPE, port:symPort)){
  exit(0);
}

if(version_is_less(version:symVer, test_version:"5.2"))
{
  report = report_fixed_ver(installed_version:symVer, fixed_version:"5.2");
  security_message(port:symPort, data:report);
  exit(0);
}
