# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103837");
  script_version("2025-04-29T05:39:55+0000");
  script_tag(name:"last_modification", value:"2025-04-29 05:39:55 +0000 (Tue, 29 Apr 2025)");
  script_tag(name:"creation_date", value:"2013-11-26 12:13:03 +0100 (Tue, 26 Nov 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("IPMI 'No Auth' Access Mode Enabled (IPMI Protocol)");

  # nb: No attacking request (just using previously gathered info) so no ACT_ATTACK
  script_category(ACT_GATHER_INFO);

  script_family("Default Accounts");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  # nb: No need to disable via default_credentials/disable_default_account_checks or
  # gb_default_credentials_options.nasl because this isn't doing any login...
  script_dependencies("gb_ipmi_detect.nasl", "global_settings.nasl");
  script_require_udp_ports("Services/udp/ipmi", 623);
  script_mandatory_keys("ipmi/no_auth_supported");
  script_exclude_keys("keys/is_private_lan");

  script_tag(name:"summary", value:"The remote Intelligent Platform Management Interface (IPMI)
  service has the 'No Auth' access mode enabled.");

  script_tag(name:"vuldetect", value:"Evaluates information gathered by the VT 'Intelligent Platform
  Management Interface (IPMI) Detection (IPMI Protocol)' (OID: 1.3.6.1.4.1.25623.1.0.103835).

  Note:

  If the scanned network is e.g. a private LAN which contains systems not accessible to the public
  (access restricted) and it is accepted that the target host is accessible without authentication
  please set the 'Network type' configuration of the following VT to 'Private LAN':

  Global variable settings (OID: 1.3.6.1.4.1.25623.1.0.12288)");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"solution", value:"Disable the 'No Auth' access mode. Please contact the vendor /
  consult the device manual for more information.");

  script_xref(name:"URL", value:"https://www.cisa.gov/news-events/alerts/2013/07/26/risks-using-intelligent-platform-management-interface-ipmi");
  script_xref(name:"URL", value:"http://fish2.com/ipmi/");

  exit(0);
}

include("port_service_func.inc");
include("host_details.inc");
include("network_func.inc");

# nb: This might be acceptable from user side if the system is located within a restricted LAN so
# allow this case via the configuration within global_settings.nasl.
if (is_private_lan())
  exit(0);

port = service_get_port(default:623, ipproto:"udp", proto:"ipmi");

if (get_kb_item("ipmi/" + port + "/no_auth_supported")) {

  # nb:
  # - Store the reference from this one to gb_ipmi_detect.nasl to show a cross-reference within the
  #   reports
  # - We don't want to use get_app_* functions as we're only interested in the cross-reference here
  register_host_detail(name:"detected_by", value:"1.3.6.1.4.1.25623.1.0.103835"); # gb_ipmi_detect.nasl
  register_host_detail(name:"detected_at", value:port + "/udp");

  report = "The remote IPMI service has the 'No Auth' access mode enabled.";
  security_message(port:port, proto:"udp", data:report);
  exit(0);
}

exit(99);
