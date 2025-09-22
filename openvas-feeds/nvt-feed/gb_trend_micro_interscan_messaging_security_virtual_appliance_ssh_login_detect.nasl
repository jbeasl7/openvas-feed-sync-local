# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105253");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-04-13 15:03:11 +0200 (Mon, 13 Apr 2015)");

  script_tag(name:"qod_type", value:"package");

  script_name("Trend Micro Interscan Messaging Security Virtual Appliance (IMSVA) Detection (SSH Login)");

  script_tag(name:"summary", value:"SSH login-based detection of Trend Micro Interscan Messaging Security Virtual Appliance (IMSVA).");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("IMSVA/system");
  exit(0);
}

include("host_details.inc");

if( ! system = get_kb_item( "IMSVA/system" ) )
  exit( 0 );

if( "IMSVA" >!< system )
  exit( 0 );

port = get_kb_item( "IMSVA/ssh-login/port" );

version = "unknown";
build = "unknown";

# IMSVA 9.0-Build_Linux_1383
match = eregmatch( pattern:"IMSVA ([0-9.]+)-Build_Linux_([0-9]+)", string:system );

if( ! isnull( match[1] ) ) {
  version = match[1];
  set_kb_item( name:"trend_micro/imsva/ssh-login/" + port + "/concluded", value:match[0] );
}

if( ! isnull( match[2] ) )
  build = match[2];

set_kb_item( name:"trend_micro/imsva/detected", value:TRUE );
set_kb_item( name:"trend_micro/imsva/ssh-login/port", value:port );
set_kb_item( name:"trend_micro/imsva/ssh-login/" + port + "/version", value:version );
set_kb_item( name:"trend_micro/imsva/ssh-login/" + port + "/build", value:build );

exit( 0 );
