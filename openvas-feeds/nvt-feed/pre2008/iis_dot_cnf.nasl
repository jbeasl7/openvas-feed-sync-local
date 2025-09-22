# SPDX-FileCopyrightText: 2003 John Lampe
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10575");
  script_version("2025-04-11T05:40:28+0000");
  script_tag(name:"last_modification", value:"2025-04-11 05:40:28 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2002-1717");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Microsoft IIS '.cnf' File Leakage Vulnerability - Active Check");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2003 John Lampe");
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("microsoft/iis/http/detected");

  script_xref(name:"URL", value:"http://www.safehack.com/Advisory/IIS5webdir.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4078");

  script_tag(name:"solution", value:"If you do not need .cnf files, then delete them, otherwise use
  suitable access control lists to ensure that the .cnf files are not world-readable by Anonymous users.");

  script_tag(name:"summary", value:"The IIS web server may allow remote users to read sensitive information
  from .cnf files. This is not the default configuration.

  Example, http://example.com/_vti_pvt%5csvcacl.cnf, access.cnf,
  svcacl.cnf, writeto.cnf, service.cnf, botinfs.cnf,
  bots.cnf, linkinfo.cnf and services.cnf");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

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

fl[0] = "/_vti_pvt%5caccess.cnf";
fl[1] = "/_vti_pvt%5csvcacl.cnf";
fl[2] = "/_vti_pvt%5cwriteto.cnf";
fl[3] = "/_vti_pvt%5cservice.cnf";
fl[4] = "/_vti_pvt%5cservices.cnf";
fl[5] = "/_vti_pvt%5cbotinfs.cnf";
fl[6] = "/_vti_pvt%5cbots.cnf";
fl[7] = "/_vti_pvt%5clinkinfo.cnf";

for(i = 0; fl[i]; i++) {
  if(http_is_cgi_installed_ka(item:fl[i], port:port)){
    res = http_keepalive_send_recv(data:http_get(item:fl[i], port:port), port:port, bodyonly:TRUE);
    data  = "The IIS web server may allow remote users to read sensitive information from .cnf files. This is not the default configuration.";
    data += '\n\nExample : requesting ' + fl[i] + ' produces the following data :\n\n' + res;
    security_message(port:port, data:data);
    exit(0);
  }
}

exit(99);
