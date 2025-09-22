# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140140");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-02-01 12:25:05 +0100 (Wed, 01 Feb 2017)");
  script_name("EMC Data Domain Detection (SSH Login)");

  script_tag(name:"summary", value:"SSH login-based detection of EMC Data Domain.");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("emc/data_domain_os/uname");
  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

if( ! uname = get_kb_item( "emc/data_domain_os/uname" ) ) exit( 0 );

if("Data Domain OS" >!< uname ) exit( 0 );

set_kb_item( name:"emc/data_domain/installed", value:TRUE );

# Welcome to Data Domain OS 6.0.0.9-544198
vb = eregmatch( pattern:'Data Domain OS ([0-9.]+[^-]+)-([0-9]+)', string:uname );

if( ! isnull( vb[1] ) )
  set_kb_item( name:"emc/data_domain/version/ssh", value:vb[1] );

if( ! isnull( vb[2] ) )
  set_kb_item( name:"emc/data_domain/build/ssh", value:vb[2] );

model = ssh_cmd_exec( cmd:"system show modelno" );

if( ! isnull( model ) )
{
  set_kb_item( name:"emc/data_domain/model/ssh", value:model );
  if( "DD VE" >< model )
    set_kb_item( name:"emc/data_domain/is_vm/ssh", value:TRUE );
}

exit( 0 );
