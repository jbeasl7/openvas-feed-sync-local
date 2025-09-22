# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803840");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-08-26 19:22:05 +0530 (Mon, 26 Aug 2013)");
  script_name("mooSocial Multiple Vulnerabilities");

  script_tag(name:"summary", value:"mooSocial is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to
  read the cookie or not.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Input passed via HTTP GET request is used in '$path' variable is not properly
  validating '../'(dot dot) sequences with null byte (%00) at the end.

  - Input passed via 'onerror' and 'onmouseover' parameters are not properly
  sanitised before being returned to the user.");

  script_tag(name:"affected", value:"mooSocial version 1.3, other versions may also be affected.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML or script
  code in a user's browser session and obtain potentially sensitive information
  to execute arbitrary local scripts in the context of the webserver.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://1337day.com/exploit/21160");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/27871");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2013080192");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/moosocial-13-cross-site-scripting-local-file-inclusion");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

foreach dir (make_list_unique("/", "/moosocial", "/social", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item:string(dir,"/"),  port:port);

  if('>mooSocial' >< res && 'www.moosocial.com' >< res)
  {
    url = dir + '/tags/view/"><img src="a" onerror="alert(document.cookie)"';

    if(http_vuln_check(port:port, url:url, check_header:TRUE,
                       pattern:"alert\(document\.cookie\)",
                       extra_check: ">mooSocial"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
