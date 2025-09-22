# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800312");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2008-12-05 15:00:57 +0100 (Fri, 05 Dec 2008)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-5296");
  script_name("Gallery Unspecified Security Bypass Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32817");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32440");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/46804");
  script_xref(name:"URL", value:"http://gallery.menalto.com/last_official_G1_releases");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to bypass authentication and gain
  administrative access to the application, if register_globals is enabled.");

  script_tag(name:"affected", value:"Gallery Version 1.5.x before 1.5.10 and 1.6 before 1.6-RC3 on all
  platform.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of authentication cookies.");

  script_tag(name:"solution", value:"Update to version 1.5.10 or 1.6-RC3.");

  script_tag(name:"summary", value:"Gallery is prone to a security bypass vulnerability.");

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

foreach dir (make_list_unique("/gallery", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:port);
  if(!rcvRes)
    continue;

  if("Powered by Gallery" >< rcvRes)
  {
    gallVer = eregmatch(pattern:"([0-9.]+)(-[A-Z0-9]+)? -", string:rcvRes);
    gallVer = ereg_replace(pattern:" -", string:gallVer[0], replace:"");
    gallVer = ereg_replace(pattern:"-", string:gallVer, replace:".");

    if(gallVer != NULL)
    {
      if(gallVer =~ "^1\.5" && version_in_range(version:gallVer, test_version:"1.5", test_version2:"1.5.9")){
        security_message(port:port);
        exit(0);
      }
      if(gallVer =~ "^1\.6" && version_in_range(version:gallVer, test_version:"1.6", test_version2:"1.6.RC2")){
        security_message(port:port);
        exit(0);
      }
    }
  }
}

exit(99);
