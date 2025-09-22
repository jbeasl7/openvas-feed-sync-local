# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108547");
  script_version("2025-04-29T05:39:55+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-04-29 05:39:55 +0000 (Tue, 29 Apr 2025)");
  script_tag(name:"creation_date", value:"2019-02-09 16:58:00 +0100 (Sat, 09 Feb 2019)");
  script_name("Unprotected OSSEC/Wazuh ossec-authd (authd Protocol)");

  # nb: No attacking request (just using previously gathered info) so no ACT_ATTACK
  script_category(ACT_GATHER_INFO);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2019 Greenbone AG");
  # nb: No need to disable via default_credentials/disable_default_account_checks or
  # gb_default_credentials_options.nasl because this isn't doing any login...
  script_dependencies("gb_ossec-authd_detect.nasl", "global_settings.nasl");
  script_mandatory_keys("ossec_wazuh/authd/no_auth");
  script_require_ports("Services/ossec-authd", 1515);
  script_exclude_keys("keys/is_private_lan");

  script_tag(name:"summary", value:"The remote OSSEC/Wazuh ossec-authd service is not protected by
  password authentication or client certificate verification.");

  script_tag(name:"vuldetect", value:"Evaluate if the remote OSSEC/Wazuh ossec-authd service is
  protected by password authentication or client certificate verification.

  Note:

  If the scanned network is e.g. a private LAN which contains systems not accessible to the public
  (access restricted) and it is accepted that the target host is accessible without authentication
  please set the 'Network type' configuration of the following VT to 'Private LAN':

  Global variable settings (OID: 1.3.6.1.4.1.25623.1.0.12288)");

  script_tag(name:"insight", value:"It was possible to connect to the remote OSSEC/Wazuh ossec-authd
  service without providing a password or a valid client certificate.");

  script_tag(name:"impact", value:"This issue may be misused by a remote attacker to register
  arbitrary agents at the remote service or overwrite the registration of existing ones taking them
  out of service.");

  script_tag(name:"solution", value:"Enable password authentication or client certificate
  verification within the configuration of ossec-authd. Please see the manual of this service for
  more information.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("port_service_func.inc");
include("network_func.inc");
include("host_details.inc");

# nb: This might be acceptable from user side if the system is located within a restricted LAN so
# allow this case via the configuration within global_settings.nasl.
if( is_private_lan() )
  exit( 0 );

port = service_get_port( default:1515, proto:"ossec-authd" );
if( ! get_kb_item( "ossec_wazuh/authd/" + port + "/no_auth" ) )
  exit( 99 );

# nb:
# - Store the reference from this one to gb_ossec-authd_detect.nasl to show a cross-reference within
#   the reports
# - We don't want to use get_app_* functions as we're only interested in the cross-reference here
register_host_detail( name:"detected_by", value:"1.3.6.1.4.1.25623.1.0.108546" ); # gb_ossec-authd_detect.nasl
register_host_detail( name:"detected_at", value:port + "/tcp" );

security_message( port:port );
exit( 0 );
