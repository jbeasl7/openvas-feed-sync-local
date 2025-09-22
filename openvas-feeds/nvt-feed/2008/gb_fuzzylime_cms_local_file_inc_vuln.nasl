# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800314");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2008-12-15 15:44:51 +0100 (Mon, 15 Dec 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-5291");
  script_name("fuzzylime cms code/track.php Local File Inclusion Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32865");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32475");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7231");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will cause inclusion and execution of arbitrary
  files from local resources via directory traversal attacks.");

  script_tag(name:"affected", value:"fuzzylime cms version 3.03 and prior.");

  script_tag(name:"insight", value:"The flaw is caused due improper handling of input passed to p parameter
  in code/track.php file when the url, title and excerpt form parameters
  are set to non-null values.");

  script_tag(name:"solution", value:"Update to fuzzylime cms version 3.03a or later.");

  script_tag(name:"summary", value:"fuzzylime CMS is prone to Local File Inclusion vulnerability.");

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

foreach path (make_list_unique("/fuzzylime/_cms303", http_cgi_dirs(port:port)))
{

  if(path == "/") path = "";

  rcvRes = http_get_cache(item: path + "/docs/readme.txt", port:port);
  if(!rcvRes)
    continue;

  if("fuzzylime (cms)" >< rcvRes)
  {
    cmsVer = eregmatch(pattern:"v([0-9.]+)", string:rcvRes);
    if(cmsVer[1] != NULL)
    {
      if(version_is_less_equal(version:cmsVer[1], test_version:"3.03")){
        report = report_fixed_ver(installed_version:cmsVer[1], vulnerable_range:"Less than or equal to 3.03");
        security_message(port: port, data: report);
        exit(0);
      }
    }
  }
}

exit(99);
