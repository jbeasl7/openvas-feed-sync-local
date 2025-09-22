# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803184");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2013-03-18 13:55:51 +0530 (Mon, 18 Mar 2013)");

  script_name("Petite Annonce <= 1.0 'categoriemoteur' XSS Vulnerability");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/120816/");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2013/Mar/143");

  script_tag(name:"summary", value:"Petite Annonce is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Input passed via the 'categoriemoteur' GET parameter to the
  'moteur-prix.php' file is not properly sanitized before being used.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML or web script in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"Petite Annonce version 1.0 is known to be affected. Other
  versions might be affected as well.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

foreach dir(make_list_unique("/", "/annonce", http_cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  res = http_get_cache(item:dir + "/index.html", port:port);

  if("petite annonce" >< res && ">DEPOSER UNE ANNONCE<" >< res) {
    url = dir + '/annonce/moteur-prix.php?categoriemoteur=1"><script>alert(document.cookie);</script>';
    if(http_vuln_check(port:port, url:url, check_header:TRUE,
                       pattern:"><script>alert\(document\.cookie\);</script>",
                       extra_check:make_list("regionmoteur.value", "categoriemoteur.value"))) {
      report = http_report_vuln_url(port:port, url:url, url_only:TRUE);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
