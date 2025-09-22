# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102114");
  script_version("2025-04-16T05:39:43+0000");
  script_tag(name:"last_modification", value:"2025-04-16 05:39:43 +0000 (Wed, 16 Apr 2025)");
  script_tag(name:"creation_date", value:"2024-10-28 06:44:43 +0000 (Mon, 28 Oct 2024)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("KRB5 Authorization"); # nb: Don't change the script name, this name is hardcoded within some manager functions...
  script_category(ACT_SETTINGS);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Credentials");

  # The following preferences are used in OSPD-OpenVAS and the ids are hardcoded there.
  script_add_preference(name:"KRB5 login:", type:"entry", value:"", id:1);
  script_add_preference(name:"KRB5 password:", type:"password", value:"", id:2);
  script_add_preference(name:"KRB5 realm:", type:"entry", value:"", id:3);
  script_add_preference(name:"KRB5 kdc:", type:"entry", value:"", id:4);

  script_tag(name:"summary", value:"This script allows users to enter the information
  required to authorize and login via KRB5.

  These data are used by tests that require authentication.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

krb5_login    = script_get_preference( "KRB5 login:", id:1 );
krb5_password = script_get_preference( "KRB5 password:", id:2 );
krb5_realm    = script_get_preference( "KRB5 realm:", id:3 );
krb5_kdc      = script_get_preference( "KRB5 kdc:", id:4 );

if( krb5_login )    set_kb_item( name:"KRB5/login_filled/0", value:krb5_login );
if( krb5_password ) set_kb_item( name:"KRB5/password_filled/0", value:krb5_password );
if( krb5_realm )    set_kb_item( name:"KRB5/realm_filled/0", value:krb5_realm );
if( krb5_kdc )      set_kb_item( name:"KRB5/kdc_filled/0", value:krb5_kdc );

exit( 0 );
