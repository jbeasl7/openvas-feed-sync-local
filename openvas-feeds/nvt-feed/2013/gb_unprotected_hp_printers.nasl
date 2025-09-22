# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:hp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103676");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"creation_date", value:"2013-03-08 11:51:27 +0100 (Fri, 08 Mar 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("HP Printers Unprotected Access (HTTP)");

  # nb: No attacking request (just access a default page depending on the printer model) currently
  # (see no_default_auth code in hp_printers.inc) so no ACT_ATTACK.
  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Default Accounts");

  # nb: No need to disable via default_credentials/disable_default_account_checks or
  # gb_default_credentials_options.nasl because this isn't doing any login (at least currently)...
  script_dependencies("gb_hp_printer_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("hp/printer/http/detected", "hp/printer/model");

  script_tag(name:"summary", value:"The remote HP Printer is not protected by a password.");

  script_tag(name:"vuldetect", value:"Checks if credentials are required to access the device.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration without requiring authentication.");

  script_tag(name:"solution", value:"Set a password.");

  exit(0);
}

# nb: Don't exit via islocalhost() or is_private_lan() here as such a system should be definitely
# access protected.

include("hp_printers.inc");
include("host_details.inc");
include("http_func.inc");

if( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX, service:"www" ) )
  exit( 0 );

cpe = infos["cpe"];

if( cpe !~ "^cpe:/o:hp.+_firmware")
  exit( 0 );

port = infos["port"];

if( ! model = get_kb_item( "hp/printer/model" ) )
  exit( 0 );

ret = check_hp_default_login( model:model, port:port );
if( ret && ret == 2 ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
