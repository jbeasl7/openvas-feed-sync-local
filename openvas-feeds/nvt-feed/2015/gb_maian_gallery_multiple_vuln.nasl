# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805648");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2015-06-09 15:25:55 +0530 (Tue, 09 Jun 2015)");

  script_tag(name:"qod_type", value:"exploit");
  script_name("Maian Gallery Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Maian Gallery is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"Multiple flaws exist as

  - Input passed to the 'index.php' script is not properly sanitised before being
    returned to the user.

  - Input passed to the 'cryptographp.php' script is not properly sanitised
    before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to  execute arbitrary script code in a user's browser within the
  trust relationship between their browser and the server and maliciously
  control the way a web application functions.");

  script_tag(name:"affected", value:"Maian Gallery version 2.0");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/132154");

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

mgPort = http_get_port(default:80);

if(!http_can_host_php(port:mgPort)){
  exit(0);
}

foreach dir (make_list_unique("/", "/gallery", "/maian_gallery", http_cgi_dirs( port:mgPort)))
{

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item:string(dir,"/index.php"), port:mgPort);

  if("Maian Gallery" >< rcvRes)
  {
    url = dir + "/index.php?cmd=search&keywords=1&search_type=";

    if(http_vuln_check(port:mgPort, url:url, check_header:FALSE,
                       pattern:"You have an error in your SQL syntax"))
    {
      security_message(port:mgPort);
      exit(0);
    }
  }
}

exit(99);
