# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140102");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-12-28 09:34:09 +0100 (Wed, 28 Dec 2016)");
  script_name("vSphere Data Protection Detection");

  script_tag(name:"summary", value:"This script performs SSH based detection of vSphere Data Protection");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("vmware/vSphere_Data_Protection/rls");
  exit(0);
}

include("host_details.inc");

if( ! rls = get_kb_item( "vmware/vSphere_Data_Protection/rls" ) ) exit( 0 );

cpe = 'cpe:/a:vmware:vsphere_data_protection';
version ="unknown";

set_kb_item( name:"vmware/vSphere_Data_Protection/installed", value:TRUE );

# <product>vSphere Data Protection 6.1</product>
# <version>6.1.0.173</version>
# <fullVersion>6.1.0.173</fullVersion>
# <vendor>VMware</vendor>
# <vendorUUID/>
# <productRID/>
# <vendorURL>http://www.vmware.com/</vendorURL>
# <productURL/>
# <supportURL/>
# <releaseDate>20150813220343.000000+000</releaseDate>
# <description/>

v = eregmatch( pattern:'<version>([0-9.]+[^<]+)</version>', string:rls );

if( ! isnull( v[1] ) )
{
  version = v[1];
  cpe += ':' + version;
  set_kb_item( name:"vmware/vSphere_Data_Protection/version", value:version );
}

register_product( cpe:cpe, location:"ssh", service:"ssh" );

report = build_detection_report( app:"vSphere Data Protection", version:version, install:"ssh", cpe:cpe, concluded:v[0] );
log_message( port:0, data:report);

exit( 0 );

