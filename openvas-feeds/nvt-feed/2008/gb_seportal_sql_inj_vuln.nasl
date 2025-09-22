# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800143");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2008-11-27 14:04:10 +0100 (Thu, 27 Nov 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2008-5191");
  script_name("SePortal poll.php SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/30865");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/29996");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/5960");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful attack could lead to execution of arbitrary SQL queries.");

  script_tag(name:"affected", value:"SePortal Version 2.4 and prior on all running platform.");

  script_tag(name:"insight", value:"Input passed to the poll_id parameter in poll.php and to sp_id parameter
  in staticpages.php files are not properly sanitised before being used in an SQL query.");

  script_tag(name:"solution", value:"Upgrade to SePortal Version 2.5 or later");

  script_tag(name:"summary", value:"SePortal is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("version_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

foreach dir( make_list_unique( "/seportal", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  rcvRes = http_get_cache(item:string(dir + "/index.php"), port:port);
  if(!rcvRes) continue;

  if("SePortal<" >< rcvRes)
  {
    sepVer = eregmatch(string:rcvRes, pattern:"SePortal<.+ ([0-9]\.[0-9.]+)");
    if(sepVer[1] != NULL)
    {
      if(version_is_less_equal(version:sepVer[1], test_version:"2.4")){
        report = report_fixed_ver(installed_version:sepVer[1], vulnerable_range:"Less than or equal to 2.4");
        security_message(port: port, data: report);
      }
    }
    exit(0);
  }
}

exit(99);
