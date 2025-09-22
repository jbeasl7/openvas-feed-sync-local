# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14269");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"OSVDB", value:"8657");
  script_xref(name:"OSVDB", value:"8658");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_name("YaPiG Remote Server-Side Script Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to YaPiG 0.92.2 or later.");

  script_tag(name:"summary", value:"The remote version of YaPiG may allow a remote attacker to execute
  malicious scripts on a vulnerable system.");

  script_tag(name:"insight", value:"This issue exists due to a lack of sanitization of user-supplied data.
  It is reported that an attacker may be able to upload content that will be saved on the server with a '.php'
  extension.  When this file is requested by the attacker, the contents of the file will be parsed and executed by the
  PHP engine, rather than being sent.");

  script_tag(name:"impact", value:"Successful exploitation of this issue may allow an attacker to execute malicious
  script code on a vulnerable server.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-08/0756.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10891");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if (!http_can_host_php(port:port))
  exit(0);

foreach dir( make_list_unique( "/yapig", "/gallery", "/photos", "/photo", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  res = http_get_cache(item:string(dir, "/"), port:port);
  if(!res)
    continue;

  #Powered by <a href="http://yapig.sourceforge.net" title="Yet Another PHP Image Gallery">YaPig</a> V0.92b
  if(egrep(pattern:"Powered by .*YaPig.* V0\.([0-8][0-9][^0-9]|9([01]|2[ab]))", string:res)) {
    security_message( port:port );
    exit( 0 );
  }
}

exit( 99 );
