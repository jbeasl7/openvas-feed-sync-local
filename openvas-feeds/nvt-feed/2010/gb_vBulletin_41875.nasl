# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vbulletin:vbulletin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100723");
  script_version("2025-05-29T05:40:25+0000");
  script_tag(name:"last_modification", value:"2025-05-29 05:40:25 +0000 (Thu, 29 May 2025)");
  script_tag(name:"creation_date", value:"2010-07-23 13:21:58 +0200 (Fri, 23 Jul 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("vBulletin <= 3.8.6 'faq.php' Information Disclosure Vulnerability - Active Check");

  script_xref(name:"URL", value:"https://web.archive.org/web/20200229180801/http://www.securityfocus.com/bid/41875");
  script_xref(name:"URL", value:"http://www.vbulletin.com/forum/showthread.php?357818-Security-Patch-Release-3.8.6-PL1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/512575");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("vbulletin_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("vbulletin/http/detected");

  script_tag(name:"summary", value:"vBulletin is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Successful exploits can allow attackers to obtain potentially
  sensitive information which may aid in other attacks.");

  script_tag(name:"affected", value:"vBulletin 3.8.6 is affected, prior versions may also be
  vulnerable.");

  script_tag(name:"solution", value:"The vendor has released a patch to address this issue. Please
  see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = string(dir, "/faq.php?s=&do=search&q=database&match=all&titlesonly=0");

if(buf = http_vuln_check(port:port, url:url, pattern:"Database")) {
  if("Name:" >< buf && "Host:" >< buf && "Port:" >< buf && "Username:" >< buf && "Password:" >< buf) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
