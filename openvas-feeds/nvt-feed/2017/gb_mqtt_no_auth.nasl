# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140167");
  script_version("2025-04-29T05:39:55+0000");
  script_tag(name:"last_modification", value:"2025-04-29 05:39:55 +0000 (Tue, 29 Apr 2025)");
  script_tag(name:"creation_date", value:"2017-02-17 16:32:23 +0100 (Fri, 17 Feb 2017)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("MQTT Broker Does Not Require Authentication (TCP)");

  # nb: No attacking request (just using previously gathered info) so no ACT_ATTACK
  script_category(ACT_GATHER_INFO);

  script_family("Default Accounts");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  # nb: No need to disable via default_credentials/disable_default_account_checks or
  # gb_default_credentials_options.nasl because this isn't doing any login...
  script_dependencies("gb_mqtt_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/mqtt", 1883);
  script_mandatory_keys("mqtt/no_user_pass");
  script_exclude_keys("keys/islocalhost", "keys/is_private_lan");

  script_tag(name:"summary", value:"The remote MQTT broker does not require authentication.");

  script_tag(name:"vuldetect", value:"Checks if authentication is required for the remote MQTT
  broker.

  Notes:

  - No scan result is expected if localhost (127.0.0.1) was scanned (self scanning)

  - If the scanned network is e.g. a private LAN which contains systems not accessible to the public
  (access restricted) and it is accepted that the target host is accessible without authentication
  please set the 'Network type' configuration of the following VT to 'Private LAN':

  Global variable settings (OID: 1.3.6.1.4.1.25623.1.0.12288)");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information.");

  script_tag(name:"solution", value:"Enable authentication.");

  script_xref(name:"URL", value:"https://www.heise.de/newsticker/meldung/MQTT-Protokoll-IoT-Kommunikation-von-Reaktoren-und-Gefaengnissen-oeffentlich-einsehbar-3629650.html");

  exit(0);
}

# nb: No point in reporting on self scans via 127.0.0.1 as services are often just bound to just
# 127.0.0.1 and thus not accessible externally...
if( islocalhost() )
  exit( 0 );

include("port_service_func.inc");
include("network_func.inc");
include("host_details.inc");

# nb: This might be acceptable from user side if the system is located within a restricted LAN so
# allow this case via the configuration within global_settings.nasl.
if( is_private_lan() )
  exit( 0 );

if( ! port = service_get_port( default:1883, proto:"mqtt" ) )
  exit( 0 );

if( ! get_kb_item( "mqtt/" + port + "/no_user_pass" ) )
  exit( 99 );

# nb:
# - Store the reference from this one to gb_mqtt_detect.nasl to show a cross-reference within the
#   reports
# - We don't want to use get_app_* functions as we're only interested in the cross-reference here
register_host_detail( name:"detected_by", value:"1.3.6.1.4.1.25623.1.0.140166" ); # gb_mqtt_detect.nasl
register_host_detail( name:"detected_at", value:port + "/tcp" );

security_message( port:port );
exit( 0 );
