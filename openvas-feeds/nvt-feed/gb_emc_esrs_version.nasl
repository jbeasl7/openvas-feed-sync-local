# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140136");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-01-31 14:38:46 +0100 (Tue, 31 Jan 2017)");
  script_name("EMC Secure Remote Services Detection");
  script_tag(name:"summary", value:"This script performs SSH based detection of EMC Secure Remote Services");
  script_tag(name:"qod_type", value:"package");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ems/esrs/rls");
  exit(0);
}

include("host_details.inc");

# Example: 318.0008.0
if( ! version = get_kb_item( "ems/esrs/rls" ) ) exit( 0 );

cpe = 'cpe:/a:emc:secure_remote_services:' + version;

register_product( cpe:cpe, location:"ssh", service:"ssh");

report = build_detection_report( app:"EMC Secure Remote Services", version:version, install:"ssh", cpe:cpe, concluded:"/etc/esrs-release");

log_message( port:0, data:report );

exit( 0 );



