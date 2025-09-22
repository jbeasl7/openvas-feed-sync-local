# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108489");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-11-28 14:02:54 +0100 (Wed, 28 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Western Digital My Cloud Products Detection (SNMP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"SNMP based detection of Western Digital My Cloud products.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("snmp_func.inc");

port    = snmp_get_port( default:161 );
sysdesc = snmp_get_sysdescr( port:port );

# nb: EX2Ultra banner is e.g. the following for My Cloud OS 3:
# Linux $hostname 3.10.39 #1 SMP Fri Aug 17 18:43:13 CST 2018 2014T30p5 Build-git435df54 armv7l -> 2.31.149
# Linux $hostname 3.10.39 #1 SMP Fri Aug 5 11:29:16 CST 2016 2014T30p5 Build-git3f24b4d armv7l -> 2.30.183
# and the following for My Cloud OS 5:
# Linux $hostname 4.14.22-armada-18.09.3 #1 SMP Wed Dec 2 06:35:33 UTC 2020 ga-18.09.3 Build-23 armv7l -> 5.08.115
if( ! sysdesc || sysdesc !~ "^Linux" )
  exit( 0 );

version = "unknown";

# MiBs at e.g. (linked at the Product pages like https://support.wdc.com/product.aspx?ID=905)
# http://downloads.wdc.com/nas/WDMYCLOUDEX4-MIB.txt
# http://downloads.wdc.com/nas/WDMYCLOUDEX2-MIB.txt
# http://downloads.wdc.com/nas/MYCLOUDPR2100-MIB.txt
#
# TODO/TBD: The model type isn't provided via SNMP at the 1.3.6.1.4.1.5127 tree
# but its currently unclear if the "8" in the OID below is the Model.
#
# SoftwareVersion
sw_oid = "1.3.6.1.4.1.5127.1.1.1.8.1.2.0";
sw_res = snmp_get( port:port, oid:sw_oid );
if( ! sw_res )
  exit( 0 );

# 2.30.183 (2.30.183.0116.2018)
# 2.30.196 (2.30.196.0919.2018)
# 2.31.149 (2.31.149.1015.2018)
# 5.08.115 (5.08.115.1216.2020)
vers = eregmatch( pattern:"^([0-9.]+)", string:sw_res );
if( vers[1] ) {

  version = vers[1];
  model   = "unknown";

  # HostName
  # nb: Some users are keeping the default hostname so use this as a model identifier
  mod_oid = "1.3.6.1.4.1.5127.1.1.1.8.1.3.0";
  mod_res = snmp_get( port:port, oid:mod_oid );
  if( mod_res && mod_res == "MyCloudEX2Ultra" ) {
    model = "EX2Ultra";
    set_kb_item( name:"wd-mycloud/snmp/" + port + "/concludedMod", value:mod_res );
    set_kb_item( name:"wd-mycloud/snmp/" + port + "/concludedModOID", value:mod_oid );
  }

  set_kb_item( name:"wd-mycloud/detected", value:TRUE );
  set_kb_item( name:"wd-mycloud/snmp/detected", value:TRUE );
  set_kb_item( name:"wd-mycloud/snmp/port", value:port );
  set_kb_item( name:"wd-mycloud/snmp/" + port + "/concludedVers", value:sw_res );
  set_kb_item( name:"wd-mycloud/snmp/" + port + "/concludedVersOID", value:sw_oid );
  set_kb_item( name:"wd-mycloud/snmp/" + port + "/version", value:version );
  set_kb_item( name:"wd-mycloud/snmp/" + port + "/model", value:model );
}

exit( 0 );
