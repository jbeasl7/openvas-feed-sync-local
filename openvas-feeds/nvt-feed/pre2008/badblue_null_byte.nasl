# SPDX-FileCopyrightText: 2002 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11064");
  script_version("2025-04-11T05:40:28+0000");
  script_tag(name:"last_modification", value:"2025-04-11 05:40:28 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5226");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2002-1021");
  script_name("BadBlue invalid null byte vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Web Servers");
  script_dependencies("gb_badblue_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("badblue/detected");

  script_tag(name:"solution", value:"Upgrade your software or protect it with a filtering reverse proxy.");

  script_tag(name:"summary", value:"It was possible to read the content of /EXT.INI
  (BadBlue configuration file) by sending an invalid GET request.");

  script_tag(name:"impact", value:"An attacker may exploit this vulnerability to steal the passwords.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

CPE = "cpe:/a:working_resources_inc.:badblue";

include("http_func.inc");
include("http_404.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

url = string("/ext.ini.%00.txt");
res = http_is_cgi_installed_ka(item:url, port:port);
if(res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
