# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108716");
  script_version("2025-07-11T05:42:17+0000");
  script_tag(name:"last_modification", value:"2025-07-11 05:42:17 +0000 (Fri, 11 Jul 2025)");
  script_tag(name:"creation_date", value:"2020-03-02 11:09:59 +0000 (Mon, 02 Mar 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Apache JServ Protocol (AJP) Public WAN (Internet) / Public LAN Accessible (TCP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  # nb: This is a protocol used by Apache Tomcat so "Web Servers" seems to fit the best
  script_family("Web Servers");
  script_dependencies("gb_apache_jserv_ajp_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/ajp13", 8009);
  script_mandatory_keys("apache/ajp/detected", "keys/is_public_addr");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/bnys5lvg1875dsslkkx2vmwxv833l35x");

  script_tag(name:"summary", value:"The script checks if the target host is running a service
  supporting the Apache JServ Protocol (AJP) accessible from a public WAN (Internet) / public
  LAN.");

  script_tag(name:"vuldetect", value:"Evaluate if the target host is running a service supporting
  the Apache JServ Protocol (AJP) accessible from a public WAN (Internet) / public LAN.

  Note: A configuration option 'Network type' to define if a scanned network should be seen as a
  public LAN can be found in the preferences of the following VT:

  Global variable settings (OID: 1.3.6.1.4.1.25623.1.0.12288)");

  script_tag(name:"insight", value:"When using the Apache JServ Protocol (AJP), care must be taken
  when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having
  higher trust than, for example, a similar HTTP connection. If such connections are available to an
  attacker, they can be exploited in ways that may be surprising (e.g. bypassing security checks,
  bypassing user authentication among others).");

  script_tag(name:"solution", value:"Only allow access to the AJP service from trusted sources /
  networks.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("port_service_func.inc");
include("network_func.inc");
include("host_details.inc");

if( ! is_public_addr() )
  exit( 0 );

port = service_get_port( default:8009, proto:"ajp13" );

if( ! get_kb_item( "apache/ajp/" + port + "/detected" ) )
  exit( 99 );

# nb:
# - Store the reference from this one to gb_apache_jserv_ajp_detect.nasl to show a cross-reference
#   within the reports
# - We don't want to / can't use get_app_* functions and we're only interested in the
#   cross-reference here
register_host_detail( name:"detected_by", value:"1.3.6.1.4.1.25623.1.0.108082" ); # gb_apache_jserv_ajp_detect.nasl
register_host_detail( name:"detected_at", value:port + "/tcp" );

security_message( port:port );
exit( 0 );
