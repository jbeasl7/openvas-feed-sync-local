# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96216");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-10-21 12:47:04 +0200 (Mon, 21 Oct 2013)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Get the DNS Name over WMI");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Windows");
  script_dependencies("gb_wmi_access.nasl");
  script_mandatory_keys("WMI/access_successful");

  script_tag(name:"summary", value:"The script gets the DNS Name over WMI.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("host_details.inc");

host    = get_host_ip();
usrname = get_kb_item( "SMB/login" );
passwd  = get_kb_item( "SMB/password" );

if( ! host || ! usrname || ! passwd ) exit( 0 );

domain = get_kb_item( "SMB/domain" );
if( domain ) usrname = domain + '\\' + usrname;

handle = wmi_connect( host:host, username:usrname, password:passwd );
if( ! handle ) exit( 0 );

#DomainRole
#0 (0x0) Standalone Workstation
#1 (0x1) Member Workstation
#2 (0x2) Standalone Server
#3 (0x3) Member Server
#4 (0x4) Backup Domain Controller
#5 (0x5) Primary Domain Controller

query = "select DNSHostName, Domain, DomainRole from Win32_ComputerSystem";

DNS = wmi_query( wmi_handle:handle, query:query );
wmi_close( wmi_handle:handle );

if( DNS ) {

  DNS       = split( DNS, keep:FALSE );
  val       = split( DNS[1], sep:'|', keep:FALSE );
  DNSName   = val[0];
  FQDNSName = val[1];
  DNSRole   = val[2];

  if( DNSRole == 1 || DNSRole > 2 ) {
    if( ! isnull( DNSName ) && ! isnull( FQDNSName ) ) {
      register_host_detail( name:"DNS-via-WMI-FQDNS", value:DNSName + "." + FQDNSName, desc:"Get the DNS Name over WMI" );
      set_kb_item( name:"DNS-via-WMI-FQDNS", value: DNSName + "." + FQDNSName );
    }
  }

  if( ! isnull( DNSName ) ) {
    register_host_detail( name:"DNS-via-WMI-DNS", value:DNSName, desc:"Get the DNS Name over WMI" );
    set_kb_item( name:"DNS-via-WMI-DNS", value:DNSName );
  }
}

exit( 0 );
