# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# The two entries "SMB/dont_send_ntlmv1" and "SMB/dont_send_in_cleartext"
# are not handled here yet. They are still managed in logins.nasl.

# Unlike the old code in logins.nasl, here only a single set of
# credentials is managed. Thus the strange name used for the KB.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.90023");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-06-02 00:42:27 +0200 (Mon, 02 Jun 2008)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SMB Authorization"); # nb: Don't change the script name, this name is hardcoded within some manager functions...
  script_category(ACT_SETTINGS);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Credentials");

  script_add_preference(name:"SMB login:", type:"entry", value:"", id:1); # nb: Don't change this name and id, these are hardcoded / used in GVMd
  script_add_preference(name:"SMB password:", type:"password", value:"", id:2); # nb: Don't change this name and id, these are hardcoded / used in GVMd
  script_add_preference(name:"SMB domain (optional):", type:"entry", value:"", id:3);

  script_tag(name:"summary", value:"This script allows users to enter the information
  required to authorize and login via SMB.

  These data are used by tests that require authentication.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

smb_login    = script_get_preference( "SMB login:", id:1 );
smb_password = script_get_preference( "SMB password:", id:2 );
smb_domain   = script_get_preference( "SMB domain (optional):", id:3 );

if( smb_login )    set_kb_item( name:"SMB/login_filled/0", value:smb_login );
if( smb_password ) set_kb_item( name:"SMB/password_filled/0", value:smb_password );
if( smb_domain )   set_kb_item( name:"SMB/domain_filled/0", value:smb_domain );

exit( 0 );