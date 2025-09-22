# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105600");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-04-08 12:19:03 +0200 (Fri, 08 Apr 2016)");
  script_name("Enterasys Device Detection");

  script_tag(name:"summary", value:"This script performs SSH based detection of Enterasys devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("enterasys/detected", "ssh/login/uname");
  exit(0);
}

include("host_details.inc");

uname = get_kb_item("ssh/login/uname");
if( ! uname || 'Error: Unknown: "/bin/sh"' >!< uname ) exit( 0 );

cpe = 'cpe:/h:enterasys:enterasys';
vers = 'unknown';

version = eregmatch( pattern:'Chassis Firmware Revision:\\s*([0-9.]+[^\r\n]+)', string:uname );
if( ! isnull( version[1] ) )
{
  vers = version[1];
  cpe += ':' + vers;
}

register_product( cpe:cpe, location:'ssh' );

report = 'The remote host seems to be an Enterasys device';
if( vers ) report += '\nFirmware version: ' + vers;
report += '\nCPE: ' + cpe + '\n';

log_message( port:0, data:report );
exit( 0 );

