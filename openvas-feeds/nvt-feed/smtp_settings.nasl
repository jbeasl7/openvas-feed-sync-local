# SPDX-FileCopyrightText: 2008 Michel Arboi and Renaud Deraison
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# SMTP is defined by RFC 2821. Messages are defined by RFC 2822

default_domain = "example.com";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80086");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SMTP settings");
  script_category(ACT_SETTINGS);
  script_copyright("Copyright (C) 2008 Michel Arboi and Renaud Deraison");
  script_family("Settings");

  script_add_preference(name:"Third party domain :", type:"entry", value:default_domain, id:1);
  script_add_preference(name:"From address : ", type:"entry", value:"nobody@example.com", id:2);
  script_add_preference(name:"To address : ", type:"entry", value:"postmaster@[AUTO_REPLACED_IP]", id:3);
  # nb: AUTO_REPLACED_IP and AUTO_REPLACED_ADDR are... automatically replaced!

  script_tag(name:"summary", value:"Various settings for SMTP parameters used during SMTP/Mail
  Server scanning.");

  script_tag(name:"insight", value:"Several checks need to use a third party host/domain name to
  work properly.

  The checks that rely on this are SMTP/Mail Server or DNS relay checks.

  By default, example.com is being used. However, under some circumstances, this may make leak
  packets from your network to this domain, thus compromising the privacy of your tests. You may
  want to change this value to maximize your privacy.

  Depending on the configuration of the tested environment the default domain might be 'null-routed'
  making some tests not fully reliable. In this case the default domain should be changed as well.

  Note that you absolutely need this option to be set to a *third party* domain. This means a domain
  that has *nothing to do* with the domain name of the network you are testing.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

fromaddr = script_get_preference( "From address : ", id:2 );
if( ! fromaddr )
  fromaddr = "nobody@example.com";

toaddr = script_get_preference( "To address : ", id:3 );
if( ! toaddr )
  toaddr = "postmaster@[AUTO_REPLACED_IP]";

if( "AUTO_REPLACED_IP" >< toaddr ) {
  dstip = get_host_ip();
  toaddr = ereg_replace( pattern:"AUTO_REPLACED_IP", string:toaddr, replace:dstip );
}

if( "AUTO_REPLACED_ADDR" >< toaddr ) {
  dstaddr = get_host_name();
  toaddr = ereg_replace( pattern:"AUTO_REPLACED_ADDR", string:toaddr, replace:dstaddr );
}

set_kb_item( name:"SMTP/headers/From", value:fromaddr );
set_kb_item( name:"SMTP/headers/To", value:toaddr );

domain = script_get_preference( "Third party domain :", id:1 );
if( ! domain )
  domain = default_domain;

set_kb_item( name:"Settings/third_party_domain", value:domain );

exit( 0 );
