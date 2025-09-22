# SPDX-FileCopyrightText: 2000 Alexander Strouk
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10491");
  script_version("2023-10-10T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-10-10 05:05:41 +0000 (Tue, 10 Oct 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/1578");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2000-0778");
  script_name("ASP/ASA source using Microsoft Translate f: bug - Active Check");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2000 Alexander Strouk");
  script_family("Web application abuses");
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("microsoft/iis/http/detected");

  script_tag(name:"solution", value:"Install all the latest Microsoft Security Patches (Note: This
  vulnerability is eliminated by installing Windows 2000 Service Pack 1)");

  script_tag(name:"summary", value:"There is a serious vulnerability in Windows 2000 (unpatched by SP1) that
  allows an attacker to view ASP/ASA source code instead of a processed file.

  ASP source code can contain sensitive information such as username's and
  passwords for ODBC connections.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

# nb: No get_app_location() as IIS is not "directly" affected and the initial version of
# this VT had only checked for the banner of IIS.
if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

host = http_host_name(port:port);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

url = "/global.asa\\";

req = string("GET ", url, " HTTP/1.0\r\n",
             "Host: ", host,"\r\n",
             "Translate: f\r\n\r\n");
send(socket:soc, data:req);
r = http_recv_headers2(socket:soc);
close(soc);

if(!r)
  exit(0);

if("Content-Type: application/octet-stream" >< r) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
