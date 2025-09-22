# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800141");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2008-11-26 16:25:46 +0100 (Wed, 26 Nov 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-5165");
  script_name("eTicket pri Parameter Multiple SQLi Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/30877");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/29973");
  script_xref(name:"URL", value:"http://www.eticketsupport.com/announcements/170_is_in_the_building-t91.0.html");
  script_xref(name:"URL", value:"http://www.digitrustgroup.com/advisories/web-application-security-eticket2.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful attack could allow manipulation of the database by injecting
  arbitrary SQL queries.");

  script_tag(name:"affected", value:"eTicket Version 1.5.7 and prior.");

  script_tag(name:"insight", value:"Input passed to the pri parameter of index.php, open.php, open_raw.php, and
  newticket.php is not properly sanitised before being used in SQL queries.");

  script_tag(name:"solution", value:"Update to Version 1.7.0 or later.");

  script_tag(name:"summary", value:"eTicket is prone to multiple SQL injection (SQLi)
  vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

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

foreach dir (make_list_unique("/eTicket", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:dir + "/license.txt", port:port);
  if(rcvRes && rcvRes =~ "^HTTP/1\.[01] 200" && "eTicket" >< rcvRes)
  {
    eTicVer = eregmatch(pattern:"eTicket ([0-9.]+)", string:rcvRes);
    if(eTicVer[1] != NULL)
    {
      if(version_is_less_equal(version:eTicVer[1], test_version:"1.5.7")){
        security_message(port:port);
        exit(0);
      }
    }
  }
}

exit(99);
