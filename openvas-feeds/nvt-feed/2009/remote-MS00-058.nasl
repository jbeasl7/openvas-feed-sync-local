# SPDX-FileCopyrightText: 2009 Christian Eric Edjenguele
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101003");
  script_version("2024-04-17T05:05:27+0000");
  script_tag(name:"last_modification", value:"2024-04-17 05:05:27 +0000 (Wed, 17 Apr 2024)");
  script_tag(name:"creation_date", value:"2009-03-15 20:49:44 +0100 (Sun, 15 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2000-0778");
  script_name("Microsoft IIS Information Disclosure Vulnerability (MS00-058) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Christian Eric Edjenguele");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("microsoft/iis/http/detected");

  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/security-updates/securitybulletins/2000/ms00-058");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10260");

  script_tag(name:"summary", value:"Microsoft IIS is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"This vulnerability could cause a IIS 5.0 web server to send the
  source code of certain types of web files to a visiting user.");

  script_tag(name:"affected", value:"Microsoft IIS 5.0 is known to be affected.");

  script_tag(name:"solution", value:"Microsoft has released a patch to fix this issue. Please see
  the reference for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

matches = make_array( 0, "application/octet-stream", 1, "<% @Language = 'VBScript' %>" );
host = http_host_name( port:port );

foreach asp_file( make_list( "/default.asp", "/iisstart.asp", "/localstart.asp" ) ) {

  req = string( "GET ",  asp_file, ' HTTP/1.0\r\n',
                "Host: ", host, '\r\n',
                'Translate: f\r\n\r\n' );
  reply = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( reply ) {
    r = tolower( reply );
    content_type = egrep( pattern:"Content-Type", string:r, icase:TRUE );
    if( ( "Microsoft-IIS" >< r ) && ( egrep( pattern:"^HTTP/1\.[01] 200", string:r, icase:TRUE ) ) && ( content_type && matches[0] >< content_type ) ) {
      if( egrep( pattern:matches[1], string:r, icase:TRUE ) ) {
        report = http_report_vuln_url( port:port, url:asp_file );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );
