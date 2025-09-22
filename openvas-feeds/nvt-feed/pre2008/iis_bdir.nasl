# SPDX-FileCopyrightText: 2003 John Lampe
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10577");
  script_version("2025-04-11T05:40:28+0000");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2280");
  script_tag(name:"last_modification", value:"2025-04-11 05:40:28 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Microsoft IIS 'bdir.htr' Default Files - Active Check");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2003 John Lampe");
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("microsoft/iis/http/detected");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"solution", value:"If you do not need these files, then delete them,
  otherwise use suitable access control lists to ensure that
  the files are not world-readable.");

  script_tag(name:"summary", value:"The file bdir.htr is a default IIS files which can give
  a malicious user a lot of unnecessary information about your file system.");

  script_tag(name:"impact", value:"Specifically, the bdir.htr script allows
  the user to browse and create files on hard drive.  As this
  includes critical system files, it is highly possible that
  the attacker will be able to use this script to escalate
  privileges and gain 'Administrator' access.

  Example: http://example.com/scripts/iisadmin/bdir.htr??c:");

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

url = "/scripts/iisadmin/bdir.htr";
if(http_is_cgi_installed_ka(item:url, port:port)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}
