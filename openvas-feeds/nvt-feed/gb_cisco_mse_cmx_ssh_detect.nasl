# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105462");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-11-20 12:48:40 +0100 (Fri, 20 Nov 2015)");
  script_name("Cisco Mobility Service Engine Detection (SSH)");

  script_tag(name:"summary", value:"This script performs SSH based detection of Cisco Mobility Service Engine");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("cisco_mse/status");
  exit(0);
}

status = get_kb_item("cisco_mse/status");

if( ! status || ( "Cisco Mobility Service Engine" >!< status && "Build Version" >!< status ) ) exit( 0 );

if( "Product name: Cisco Mobility Service Engine" >< status )
  version = eregmatch( pattern:'Product name: Cisco Mobility Service Engine[\r\n]+Version: ([^\r\n]+)', string:status );
else
  version = eregmatch( pattern:'Build Version\\s*:\\s*([0-9]+[^\r\n]+)', string:status );

if( ! isnull( version[1] ) )
{
  set_kb_item( name:"cisco_mse/ssh/version", value:version[1] );
  set_kb_item( name:"cisco_mse/lsc", value:TRUE );
  vers = version[1];
}

exit( 0 );
