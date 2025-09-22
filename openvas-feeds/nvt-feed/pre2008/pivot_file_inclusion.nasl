# SPDX-FileCopyrightText: 2004 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# From: loofus@0x90.org - loofus
# Subject: Pivot Remote Code Execution Vulnerability
# Date: 2004-06-17
#
# changes by rd: description and detection method
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12282");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("File Inclusion Vulnerability in Pivot");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to Pivot 1.14.1 or disable this CGI altogether");

  script_tag(name:"summary", value:"Pivot is a set of PHP scripts designed to maintain dynamic web pages.

  There is a flaw in the file module_db.php which may let an attacker execute
  arbitrary commands on the remote host by forcing the remote Pivot installation
  to include a PHP file hosted on an arbitrary third-party website.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if (! http_can_host_php(port:port) ) exit(0);

function check_dir(path)
{

 if(path == "/") path = "";

 req = http_get(item:string(path, "/modules/module_db.php?pivot_path=http://xxxxxxxxxx/"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( "http://xxxxxxxxxx/modules/module_db_xml.php" >< res )
 {
  security_message(port:port);
  exit(0);
 }
}

foreach dir (make_list_unique("/pivot", http_cgi_dirs(port:port))) check_dir(path:dir);

exit(99);
