# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805321");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-01-13 13:48:08 +0530 (Tue, 13 Jan 2015)");
  script_name("PHPads Authentication Bypass Vulnerabilities (Jan 2015)");

  script_tag(name:"summary", value:"PHPads is prone to Authentication Bypass vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET
  request and check whether it is able to read 'ads.dat' file or not.");

  script_tag(name:"insight", value:"The flaws is due to 'ads.dat' file
  which is in web root.");

  script_tag(name:"impact", value:"Successful exploitation allows to bypass
  the authentication mechanism by creating the cookies 'user' and 'pass'
  and assigning them the corresponding values taken from the 'ads.dat' file.");

  script_tag(name:"affected", value:"PHPads version 2.0.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/35535");
  script_xref(name:"URL", value:"http://secunia.com/community/advisories/33580");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

phpPort = http_get_port(default:80);
if(!http_can_host_php(port:phpPort)){
  exit(0);
}

foreach dir (make_list_unique("/", "/phpads", "/ads", http_cgi_dirs(port:phpPort)))
{

  if( dir == "/" ) dir = "";

  res = http_get_cache(item:string(dir, "/admin.php"), port:phpPort);

  if("<title>PHPads" >< res && ">PHPads<" >< res)
  {
    reqads = http_get(item:string(dir, "/ads.dat"), port:phpPort);
    resads = http_keepalive_send_recv(port:phpPort, data:reqads);

    ##Extra Check not possible
    if( resads =~ "user=[0-9a-zA-Z]+" && resads =~ "pass=[0-9a-zA-Z]+" )
    {
      report = http_report_vuln_url( port:phpPort, url:dir + '/ads.dat' );
      security_message(port:phpPort, data:report);
      exit(0);
    }
  }
}

exit(99);
