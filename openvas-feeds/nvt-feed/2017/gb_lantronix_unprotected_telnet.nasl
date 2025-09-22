# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112132");
  script_version("2025-09-10T05:38:24+0000");
  script_tag(name:"last_modification", value:"2025-09-10 05:38:24 +0000 (Wed, 10 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-11-22 11:46:00 +0100 (Wed, 22 Nov 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Lantronix Devices Unprotected Access (Telnet)");

  # nb: No attacking request (just "grabbing" a login banner) so no ACT_ATTACK
  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Default Accounts");

  # nb: No need to disable via default_credentials/disable_default_account_checks or
  # gb_default_credentials_options.nasl because this isn't doing any login (at least currently)...
  script_dependencies("gb_lantronix_device_consolidation.nasl");
  script_mandatory_keys("lantronix_device/telnet/detected");
  script_require_ports("Services/telnet", 9999);

  script_tag(name:"summary", value:"The Lantronix Device Server setup is accessible via an
  unprotected Telnet connection.");

  script_tag(name:"vuldetect", value:"Checks if credentials are required to access the device.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker to configure and
  control the device.");

  script_tag(name:"solution", value:"Disable the telnet access or protect it via a strong
  password.");

  exit(0);
}

# nb: Don't exit via islocalhost() or is_private_lan() here as such a system should be definitely
# access protected.

include("telnet_func.inc");
include("misc_func.inc");
include("dump.inc");

if( ! port = get_kb_item( "lantronix_device/telnet/port" ) )
  exit( 0 );

banner = telnet_get_banner( port:port );

if( banner && "Press Enter" >< banner && "Setup Mode" >< banner ) {
  report = "The Lantronix Device setup menu could be accessed via an unprotected telnet connection.";
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
