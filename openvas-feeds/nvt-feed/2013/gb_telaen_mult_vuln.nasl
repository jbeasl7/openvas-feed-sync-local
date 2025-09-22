# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803646");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2013-2621", "CVE-2013-2623", "CVE-2013-2624");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-04 17:02:00 +0000 (Tue, 04 Feb 2020)");
  script_tag(name:"creation_date", value:"2013-06-10 16:45:05 +0530 (Mon, 10 Jun 2013)");
  script_name("Telaen Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Jun/12");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60288");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60290");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60340");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/telaen-130-xss-open-redirection-disclosure");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to perform open redirection,
  obtain sensitive information and execute arbitrary code in a user's browser
  session in context of an affected site.");

  script_tag(name:"affected", value:"Telaen version 1.3.0 and prior");

  script_tag(name:"insight", value:"The flaws are due to:

  - Improper validation of input passed to 'f_email' parameter upon submission
    to the '/telaen/index.php' script.

  - Improper validation of user-supplied input upon submission to the
    '/telaen/redir.php' script.

  - Issue when requested for the '/telaen/inc/init.php' script.");

  script_tag(name:"solution", value:"Upgrade to Telaen version 1.3.1 or later.");

  script_tag(name:"summary", value:"Telaen is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://www.telaen.com");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

Port = http_get_port(default:80);

if(!http_can_host_php(port:Port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/telaen", "/webmail", http_cgi_dirs(port:Port)))
{
  if(dir == "/") dir = "";

  res = http_get_cache(item:string(dir, "/index.php"),  port:Port);

  if('>Powered by Telaen' >< res && 'login' >< res)
  {

    host = http_host_name(port:Port);
    req = http_get(item:string(dir, "/redir.php?http://", host, "/telaen/index.php"),  port:Port);
    res = http_keepalive_send_recv(port:Port, data:req, bodyonly:FALSE);

    if(res && res =~ "^HTTP/1\.[01] 200")
    {
      matched=  eregmatch(string:res, pattern:">http://[0-9.]+(.*)</a>");
      if(matched[1])
      {
        url = dir + matched[1];
        req = http_get(item:url, port:Port);
        res = http_keepalive_send_recv(port:Port, data:req);

        if('>Powered by Telaen' >< res && 'login' >< res){
          security_message(port:Port);
          exit(0);
        }
      }
    }
  }
}

exit(99);
