# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801202");
  script_version("2024-09-17T05:05:45+0000");
  script_cve_id("CVE-2009-4763");
  script_tag(name:"last_modification", value:"2024-09-17 05:05:45 +0000 (Tue, 17 Sep 2024)");
  script_tag(name:"creation_date", value:"2010-04-07 16:20:50 +0200 (Wed, 07 Apr 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("PhpMyVisites ClickHeat Plugin <= 2.3 Unspecified Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.phpmyvisites.us/phpmv2/CHANGELOG");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/57004");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38824");

  script_tag(name:"summary", value:"PhpMyVisites is prone to an unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PhpMyVisites version 2.3 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error related to the ClickHeat
  plugin used in phpMyVisites.");

  script_tag(name:"solution", value:"Update to version 2.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

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

foreach dir(make_list_unique("/", "/phpmv2", "/phpmyvisites", http_cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  res = http_get_cache(item:dir + "/index.php", port:port);

  if('>phpMyVisites' >< res) {

    ver = eregmatch(pattern:'"version" content="([0-9\\.]+)"', string:res);
    if(ver[1]) {
      if(version_is_less(version:ver[1], test_version:"2.4")) {
        report = report_fixed_ver(installed_version:ver[1], fixed_version:"2.4");
        security_message(port:port, data:report);
        exit(0);
      }
    }
  }
}

exit(99);
