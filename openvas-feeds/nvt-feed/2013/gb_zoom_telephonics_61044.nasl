# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103756");
  script_version("2024-06-06T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-06-06 05:05:36 +0000 (Thu, 06 Jun 2024)");
  script_tag(name:"creation_date", value:"2013-08-12 15:24:34 +0200 (Mon, 12 Aug 2013)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Multiple Zoom Telephonics Devices Multiple Security Vulnerabilities (Aug 2013) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Nucleus/banner");

  script_tag(name:"summary", value:"Multiple Zoom Telephonics devices are prone to an information
  disclosure vulnerability, an authentication bypass vulnerability and an SQL injection (SQLi)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"When UPnP services and WAN http administrative access are
  enabled, authorization and credential challenges can be bypassed by directly accessing root
  privileged abilities via a web browser URL.

  All aspects of the modem/router can be changed, altered and controlled by an attacker, including
  gaining access to and changing the PPPoe/PPP ISP credentials.");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to gain
  unauthorized access and perform arbitrary actions, obtain sensitive information, compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying
  database.");

  script_tag(name:"affected", value:"- X4 ADSL Modem and Router

  - X5 ADSL Modem and 4-port Router");

  script_tag(name:"solution", value:"Ask the Vendor for an update.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61044");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

banner = http_get_remote_headers(port: port);
if ("401 Unauthorized" >!< banner || "Server: Nucleus/" >!< banner)
  exit(0);

url = "/hag/pages/toolbox.htm";

if (http_vuln_check(port: port, url: url, pattern: "<title>Advanced Setup",
                    extra_check: make_list("WAN Configuration", "ADSL Status"))) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
