# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108166");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-05-22 09:21:05 +0200 (Mon, 22 May 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Eyes Of Network (EON) Detection (SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("eyesofnetwork/rls");

  script_tag(name:"summary", value:"SSH login-based detection of Eyes Of Network (EON).");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

if( ! rls = get_kb_item( "eyesofnetwork/rls" ) ) exit( 0 );
port = get_kb_item( "eyesofnetwork/ssh/port" );

set_kb_item( name:"eyesofnetwork/detected", value:TRUE );
set_kb_item( name:"eyesofnetwork/ssh/detected", value:TRUE );

version = "unknown";

vers = eregmatch( pattern:"EyesOfNetwork release ([0-9.]+)", string:rls );
if( vers[1] ) {
  version = vers[1];
  set_kb_item( name:"eyesofnetwork/ssh/" + port + "/version", value:version );
  set_kb_item( name:"eyesofnetwork/ssh/" + port + "/concluded", value:rls );
}

exit( 0 );
