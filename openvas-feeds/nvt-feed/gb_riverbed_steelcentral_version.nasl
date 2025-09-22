# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105789");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-06-30 13:36:05 +0200 (Thu, 30 Jun 2016)");
  script_name("Riverbed SteelCentral Version Report");

  script_tag(name:"summary", value:"This script consolidate the via ssh and/or http detected Riverbed SteelCentral version for further probes.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_riverbed_steelcentral_http_detect.nasl", "gb_riverbed_steelcentral_ssh_detect.nasl");
  script_mandatory_keys("riverbed/SteelCentral/detected");
  exit(0);
}

include("host_details.inc");
include("os_func.inc");

source = 'http';

if( ! version = get_kb_item("riverbed/SteelCentral/" + source + "/version") )
{
  source = 'ssh';
  if( ! version = get_kb_item("riverbed/SteelCentral/" + source + "/version") ) exit( 0 );
}

report_version = version;
report_app = 'Riverbed SteelCentral';

cpe = 'cpe:/a:riverbed:steelcentral:' + version;

register_product( cpe:cpe, location:source, service:"consolidated_version" );
set_kb_item( name:"riverbed/SteelCentral/installed", value:TRUE );

model = get_kb_item("riverbed/SteelCentral/" + source + "/model");
if( model )
{
  set_kb_item( name:"riverbed/SteelCentral/model", value:model );
  report_app += ' (' + model + ')';
}

release = get_kb_item("riverbed/SteelCentral/" + source + "/release");
if( release )
{
  set_kb_item( name:"riverbed/SteelCentral/release", value:release );
  report_version += ' (' + release + ')';
}

os_register_and_report( os:"Riverbed Optimization System (RiOS)", cpe:"cpe:/o:riverbed:riverbed_optimization_system", desc:"Riverbed SteelCentral Version Report", runs_key:"unixoide" );

report = build_detection_report( app:report_app, version:report_version, install:source, cpe:cpe, extra:'\nDetection source: ' + source );

log_message( data:report );
exit( 0 );

