# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105076");
  script_version("2023-08-08T05:06:11+0000");
  script_tag(name:"last_modification", value:"2023-08-08 05:06:11 +0000 (Tue, 08 Aug 2023)");
  script_tag(name:"creation_date", value:"2014-09-02 10:42:27 +0200 (Tue, 02 Sep 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SNMP Authorization"); # nb: Don't change the script name, this name is hardcoded within some manager functions...
  script_category(ACT_SETTINGS);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Credentials");
  script_dependencies("global_settings.nasl");
  script_exclude_keys("global_settings/authenticated_scans_disabled");

  script_add_preference(name:"SNMP Community:", type:"password", value:"", id:1); # nb: Don't change this name and id, these are hardcoded / used in GVMd

  # Scanner needs to be build against libsnmp or have snmpget installed for extended SNMP
  # functionality in e.g. snmp_func.inc.
  # nb: This functions should be always there since openvas-scanner version 20.08.1 / via:
  # https://github.com/greenbone/openvas-scanner/pull/594
  if(defined_func("snmpv3_get")) {
    script_add_preference(name:"SNMPv3 Username:", type:"entry", value:"", id:2); # nb: Don't change this name and id, these are hardcoded / used in GVMd
    script_add_preference(name:"SNMPv3 Password:", type:"password", value:"", id:3); # nb: Don't change this name and id, these are hardcoded / used in GVMd
    script_add_preference(name:"SNMPv3 Authentication Algorithm:", type:"radio", value:"md5;sha1", id:4); # nb: Don't change this name and id, these are hardcoded / used in GVMd
    script_add_preference(name:"SNMPv3 Privacy Password:", type:"password", value:"", id:5); # nb: Don't change this name and id, these are hardcoded / used in GVMd
    script_add_preference(name:"SNMPv3 Privacy Algorithm:", type:"radio", value:"aes;des", id:6); # nb: Don't change this name and id, these are hardcoded / used in GVMd
  }

  script_tag(name:"summary", value:"This script allows users to enter the information required to
  authorize and login via SNMP.

  These data are used by tests that require authentication.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

if( get_kb_item( "global_settings/authenticated_scans_disabled" ) )
  exit( 0 );

snmp_community = script_get_preference( "SNMP Community:", id:1 );
if( snmp_community && snmp_community != "(null)" ) {
  set_kb_item( name:"SNMP/v12c/provided_community", value:snmp_community );
}

# nb: See note above
if( defined_func( "snmpv3_get" ) ) {

  snmpv3_username = script_get_preference( "SNMPv3 Username:", id:2 );
  if( snmpv3_username && snmpv3_username != "(null)" )
    set_kb_item( name:"SNMP/v3/username", value:snmpv3_username );

  snmpv3_password = script_get_preference( "SNMPv3 Password:", id:3 );
  if( snmpv3_password && snmpv3_password != "(null)" )
    set_kb_item( name:"SNMP/v3/password", value:snmpv3_password );

  snmpv3_auth_algo = script_get_preference( "SNMPv3 Authentication Algorithm:", id:4 );
  if( snmpv3_auth_algo && snmpv3_auth_algo != "(null)" )
    set_kb_item( name:"SNMP/v3/auth_algorithm", value:snmpv3_auth_algo );

  snmpv3_priv_password = script_get_preference( "SNMPv3 Privacy Password:", id:5 );
  if( snmpv3_priv_password && snmpv3_priv_password != "(null)" )
    set_kb_item( name:"SNMP/v3/privacy_password", value:snmpv3_priv_password );

  snmpv3_priv_algo = script_get_preference( "SNMPv3 Privacy Algorithm:", id:6 );
  if( snmpv3_priv_algo && snmpv3_priv_algo != "(null)" )
    set_kb_item( name:"SNMP/v3/privacy_algorithm", value:snmpv3_priv_algo );
}

exit( 0 );
