# SPDX-FileCopyrightText: 2002 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:trendmicro:officescan";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11074");
  script_version("2025-04-11T05:40:28+0000");
  script_tag(name:"last_modification", value:"2025-04-11 05:40:28 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2001-1151");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3438");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("OfficeScan configuration file disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("gb_trend_micro_office_scan_detect_remote.nasl");
  script_mandatory_keys("TrendMicro/OfficeScan/Installed/Remote");

  script_tag(name:"solution", value:"Upgrade OfficeScan.");

  script_tag(name:"summary", value:"Trend Micro OfficeScan Corporate Edition (Japanese version: Virus
  Buster Corporate Edition) web-based management console let anybody
  access /officescan/hotdownload without authentication.");

  script_tag(name:"impact", value:"Reading the configuration file /officescan/hotdownload/ofcscan.ini
  will reveal information on your system. More, it contains passwords that are encrypted by a weak
  specific algorithm, so they might be decrypted.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_404.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

url = "/officescan/hotdownload/ofscan.ini";
res = http_is_cgi_installed_ka(port:port, item:url);
if(!res)
  exit(99);

res = http_is_cgi_installed_ka(port:port, item:"/officescan/hotdownload/vt-test.ini");
if(res)
  exit(0);

report = http_report_vuln_url(port:port, url:url);
security_message(port:port, data:report);

exit(0);
