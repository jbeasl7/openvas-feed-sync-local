# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805021");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-12-04 12:11:44 +0530 (Thu, 04 Dec 2014)");
  script_name("Prolink PRN2001 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is Prolink PRN2001 and is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to login with default credentials");

  script_tag(name:"insight", value:"The Prolink PRN2001 is vulnerable to,

  - Incorrect User Management,

  - Exposure of Resource to Wrong Sphere.

  - Information Exposure,

  - Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS).

  - Denial of Service and

  - Security Misconfiguration.

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to sensiteve information, denial of service and
  execute arbitrary HTML and script code in a user's browser session in the
  context of an affected site.");

  script_tag(name:"affected", value:"Prolink PRN2001");

  script_tag(name:"solution", value:"No known solution was made available for at least
  one year since the disclosure of this vulnerability. Likely none will be provided
  anymore. General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/35419");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("PRN2001/banner");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:8080);

banner = http_get_remote_headers(port:port);

if(!banner || 'WWW-Authenticate: Basic realm="PRN2001"' >!< banner)
  exit(0);

host = http_host_name(port:port);

credential = "admin:password";
userpass = base64(str:credential );
req = 'GET / HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'Authorization: Basic ' + userpass + '\r\n' +
      '\r\n';
res = http_keepalive_send_recv(port:port, data:req);

if(res =~ "^HTTP/1\.[01] 200"  && ">PROLiNK Wireless Router<" >< res) {
  credential = str_replace(string:credential, find:":", replace:"/");
  report = 'It was possible to login using the following credentials:\n\n' + credential;
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
