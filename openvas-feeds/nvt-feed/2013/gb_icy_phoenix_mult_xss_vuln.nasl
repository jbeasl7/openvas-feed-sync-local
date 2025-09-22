# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803952");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2013-10-08 15:21:12 +0530 (Tue, 08 Oct 2013)");
  script_name("Icy Phoenix Multiple Cross-Site Scripting Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to steal the victim's
  cookie-based authentication credentials.");

  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it is able
  to read the string or not.");

  script_tag(name:"insight", value:'An error exists in the application which fails to properly sanitize user-supplied
  input to "subject" parameter before using it.');
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Icy Phoenix is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"affected", value:"Icy Phoenix version 2.0, Lower versions may also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/50890");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62722");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/79115");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/123446");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/117197");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

foreach dir (make_list_unique("/", "/icyphoenix", "/ip", http_cgi_dirs(port:port)))
{

  if( dir == "/" ) dir = "";

  res = http_get_cache(item: dir + "/index.php", port:port);

  if(res && (egrep(pattern:"Powered by.*Icy Phoenix.*phpBB", string:res)))
  {
    url = dir + "/index.php?>'" + '"><script>alert(01234567891);</script>=';

    match = "<script>alert\(01234567891\);</script>";
    if(http_vuln_check(port:port, url:url, check_header:TRUE,
           pattern:match))
    {
      report = http_report_vuln_url( port:port, url:url );
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
