# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800745");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2010-04-01 11:04:35 +0200 (Thu, 01 Apr 2010)");
  script_cve_id("CVE-2010-1095");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Tracking Requirements And Use Cases Cross Site Scripting vulnerability");
  script_xref(name:"URL", value:"http://vul.hackerjournals.com/?p=7357");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0491");

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to inject arbitrary
  web script or HTML via the error parameter in the context of an affected site.");

  script_tag(name:"affected", value:"Tracking Requirements and Use Cases (TRUC) version 0.11.0.");

  script_tag(name:"insight", value:"The flaw is due to an input validation error in the
  'login_reset_password_page.php' script when processing data passed via the 'error' parameter.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Tracking Requirements and Use Cases is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port)){
  exit(0);
}

foreach path (make_list_unique("/", "/truc", "/Truc", http_cgi_dirs(port:port)))
{

  if(path == "/") path = "";

  res = http_get_cache(item: path + "/login.php", port:port);
  if("TRUC" >< res)
  {
    version = eregmatch(pattern:"TRUC ([0-9.]+)", string:res);
    if(version[1] != NULL)
    {
      if(version_is_equal(version:version[1], test_version:"0.11.0")){
        security_message(port:port);
        exit(0);
      }
    }
  }
}

exit(99);
