# SPDX-FileCopyrightText: 2016 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:tutos:tutos";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111106");
  script_version("2023-12-07T05:05:41+0000");
  script_cve_id("CVE-2008-0149");
  script_tag(name:"last_modification", value:"2023-12-07 05:05:41 +0000 (Thu, 07 Dec 2023)");
  script_tag(name:"creation_date", value:"2016-06-16 16:40:16 +0200 (Thu, 16 Jun 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("TUTOS phpinfo() Information Disclosure (HTTP) - Active Check");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_tutos_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("tutos/installed");

  script_tag(name:"summary", value:"TUTOS allows remote attackers to read system information via a
  direct request to php/admin/phpinfo.php, which calls the phpinfo function.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Some of the information that can be gathered from this file
  includes: The username of the user who installed php, if they are a SUDO user, the IP address of
  the host, the web server version, the system version(unix / linux), and the root directory of the
  web server.");

  script_tag(name:"solution", value:"Delete the listed file or restrict access to it.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/php/admin/phpinfo.php";

host = http_host_name( dont_add_port:TRUE );
res = http_get_cache( item:url, port:port );
if( ! res )
  exit( 0 );

if( concl = http_check_for_phpinfo_output( data:res ) ) {
  report = http_report_vuln_url( port:port, url:url );
  report += '\nConcluded from:\n' + concl;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
