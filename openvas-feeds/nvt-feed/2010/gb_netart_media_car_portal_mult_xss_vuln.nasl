# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801454");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2010-10-05 07:29:45 +0200 (Tue, 05 Oct 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-3418");
  script_name("NetArt Media Car Portal Multiple Cross-site Scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41366");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43145");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/61728");
  script_xref(name:"URL", value:"http://pridels-team.blogspot.com/2010/09/netartmedia-car-portal-v20-xss-vuln.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"Input passed via the 'y' parameter to 'include/images.php' and
  'car_id' parameter to 'index.php' are not properly sanitised.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"NetArt Media Car Portal is prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"NetArt Media Car Portal version 2.0");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

vt_strings = get_vt_strings();

foreach dir (make_list_unique("/car_portal", "/", http_cgi_dirs(port:port))) {

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.php", port:port);

  if(">Car Portal<" >< res) {
    req = http_get(item:string(dir, '/include/images.php?y=<script>' +
                           'alert("', vt_strings["lowercase"], '")</script>'), port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if(ereg(pattern:"^HTTP/1\.[01] 200", string:res) &&
            '<script>alert(\"' + vt_strings["lowercase"] + '\")</script>' >< res) {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
