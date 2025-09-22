# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901113");
  script_version("2025-03-05T05:38:52+0000");
  script_cve_id("CVE-2010-1538");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-05-04 09:40:09 +0200 (Tue, 04 May 2010)");
  script_name("phpRAINCHECK 'print_raincheck.php' SQL injection vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/11586");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38521");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/56578");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1002-exploits/phpraincheck-sql.txt");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to execute arbitrary
  SQL queries and gain access to sensitive information.");

  script_tag(name:"affected", value:"PHP RAINCHECK 1.0.1 and prior.");

  script_tag(name:"insight", value:"The flaw is caused by an improper validation of user-supplied input
  via the 'id' parameter in print_raincheck.php that allows an attacker to manipulate SQL
  queries by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"phpRAINCHECK is prone to a SQL injection vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
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

foreach dir(make_list_unique("/", "/rainchecks", "/phprainchecks", http_cgi_dirs(port:port))) {

  install = dir;
  if(dir == "/")
    dir = "";

  res = http_get_cache(item:dir + "/settings.php", port:port);

  if('>phpRAINCHECK - Settings<' >< res) {
    ver = eregmatch(pattern:"Version: ([0-9.]+)", string:res);
    if(ver[1]) {
      if(version_is_less_equal(version:ver[1], test_version:"1.0.1")) {
        report = report_fixed_ver(installed_version:ver[1], fixed_version:"None", install_url:install);
        security_message(port:port, data:report);
        exit(0);
      }
    }
  }
}

exit(99);
