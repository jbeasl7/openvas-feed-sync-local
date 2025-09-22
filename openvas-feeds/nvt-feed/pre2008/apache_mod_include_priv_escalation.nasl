# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15554");
  script_version("2024-02-02T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:11 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11471");
  script_cve_id("CVE-2004-0940");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 03:05:26 +0000 (Fri, 02 Feb 2024)");
  script_name("Apache HTTP Server 'mod_include' Privilege Escalation Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/http_server/http/detected");

  script_tag(name:"summary", value:"The remote web server appears to be running a version
  of Apache HTTP Server that is older than version 1.3.33.");

  script_tag(name:"insight", value:"This version is vulnerable to a local buffer overflow
  in the get_tag() function of the module 'mod_include' when a specially crafted document
  with malformed server-side includes is requested though an HTTP session.");

  script_tag(name:"impact", value:"Successful exploitation can lead to execution of arbitrary
  code with escalated privileges, but requires that server-side includes (SSI) is enabled.");

  script_tag(name:"solution", value:"Disable SSI or update to a newer version when available.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

banner = http_get_remote_headers( port:port );
if( ! banner )
  exit( 0 );

serv = strstr( banner, "Server" );
if( ereg( pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/(1\.([0-2]\.|3\.([0-9][^0-9]|[0-2][0-9]|3[0-2])))", string:serv ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
