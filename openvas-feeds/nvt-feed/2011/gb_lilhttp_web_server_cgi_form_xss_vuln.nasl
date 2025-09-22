# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902437");
  script_version("2023-10-27T05:05:28+0000");
  script_cve_id("CVE-2002-1009");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2011-06-02 11:54:09 +0200 (Thu, 02 Jun 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Lil' HTTP Server <= 2.2 XSS Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("LilHTTP/banner");

  script_tag(name:"summary", value:"LilHTTP Web Server is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied
  input, passed in the 'name' and 'email' parameter in 'cgitest.html', when handling the
  'CGI Form Demo' application.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to plant XSS
  backdoors and inject arbitrary SQL statements via crafted XSS payloads.");

  script_tag(name:"affected", value:"LilHTTP Server version 2.2 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/101758/lilhttp-xss.txt");
  script_xref(name:"URL", value:"http://www.securityhome.eu/exploits/exploit.php?eid=5477687364de02d6a4c2430.52315196");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

banner = http_get_remote_headers(port: port);
if (!banner || "Server: LilHTTP" >!< banner)
  exit(0);

url = "/pbcgi.cgi";

data = "name=%3Cscript%3Ealert%28%27VT-XSS-TEST%27%29%3C%2Fscript%3E&email=";

req = http_post(port: port, item: url, data: data);
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "^HTTP/1\.[01] 200" && "name=<script>alert('VT-XSS-TEST')</script>" >< res){
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
