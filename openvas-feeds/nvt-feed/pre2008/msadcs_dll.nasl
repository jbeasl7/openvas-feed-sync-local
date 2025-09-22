# SPDX-FileCopyrightText: 2000 Roelof Temmingh
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10357");
  script_version("2025-04-11T05:40:28+0000");
  script_tag(name:"last_modification", value:"2025-04-11 05:40:28 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/529");
  script_xref(name:"IAVA", value:"1999-a-0010");
  script_xref(name:"IAVA", value:"1999-t-0003");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-1999-1011");
  script_name("Microsoft RDS / MDAC Vulnerability (MS99-025, msadcs.dll) - Active Check");
  script_category(ACT_ATTACK); # nb: Direct access to a .dll file might be already seen as an attack
  script_copyright("Copyright (C) 2000 Roelof Temmingh");
  script_family("Web Servers");
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("microsoft/iis/http/detected");

  script_tag(name:"summary", value:"The web server is probably susceptible to a common IIS vulnerability discovered by
  'Rain Forest Puppy'.");

  script_tag(name:"impact", value:"This vulnerability enables an attacker to execute arbitrary
  commands on the server with Administrator Privileges.");

  script_tag(name:"solution", value:"See Microsoft security bulletin (MS99-025) for patch information.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
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

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

cgi = "/msadc/msadcs.dll";
res = http_is_cgi_installed_ka(item:cgi, port:port);
if(res) {
  report = http_report_vuln_url(port:port, url:cgi);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
