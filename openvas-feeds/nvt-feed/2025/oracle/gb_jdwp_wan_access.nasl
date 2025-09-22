# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.119053");
  script_version("2025-07-09T05:43:50+0000");
  script_tag(name:"last_modification", value:"2025-07-09 05:43:50 +0000 (Wed, 09 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-08 11:33:12 +0000 (Tue, 08 Jul 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_name("Java Debug Wire Protocol (JDWP) Service Public WAN (Internet) / Public LAN Accessible");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_jdwp_tcp_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/jdwp", 8000);
  script_mandatory_keys("jdwp/tcp/detected", "keys/is_public_addr");

  script_xref(name:"URL", value:"https://www.wiz.io/blog/exposed-jdwp-exploited-in-the-wild");
  script_xref(name:"URL", value:"https://twitter.com/hackerfantastic/status/1103087869063704576");
  script_xref(name:"URL", value:"https://web.archive.org/web/20190306220416/https://static.hacker.house/releasez/expl0itz/jdwp-exploit.txt");

  script_tag(name:"summary", value:"The script checks if the target host is running a Java Debug
  Wire Protocol (JDWP) service accessible from a public WAN (Internet) / public LAN.");

  script_tag(name:"vuldetect", value:"Evaluate if the target host is running a JWDP service
  accessible from a public WAN (Internet) / public LAN.

  Note: A configuration option 'Network type' to define if a scanned network should be seen as a
  public LAN can be found in the preferences of the following VT:

  Global variable settings (OID: 1.3.6.1.4.1.25623.1.0.12288)");

  script_tag(name:"insight", value:"A public accessible JWDP service is generally seen as / assumed
  to be a security misconfiguration as it should be only available for debugging purposes in
  development environments. Furthermore it might be exploited by an attacker to achieve remote code
  execution (RCE) on the target host.

  Please see the references for more information.");

  script_tag(name:"solution", value:"- Only allow access to the JDWP service from trusted sources

  - Disable the service if unused / not required");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("network_func.inc");
include("port_service_func.inc");
include("host_details.inc");

if( ! is_public_addr() )
  exit( 0 );

port = service_get_port( default:8000, proto:"jdwp" );

if( get_kb_item( "jdwp/tcp/" + port + "/detected" ) ) {

  # nb:
  # - Store the reference from this one to gb_jdwp_tcp_detect.nasl to show a cross-reference within
  #   the reports
  # - We don't want to / can't use get_app_* functions and we're only interested in the
  #   cross-reference here
  register_host_detail( name:"detected_by", value:"1.3.6.1.4.1.25623.1.0.143507" ); # gb_jdwp_tcp_detect.nasl
  register_host_detail( name:"detected_at", value:port + "/tcp" );
  report = "A JDWP service is publicly available at this port.";
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
