# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813748");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-08-08 13:39:48 +0530 (Wed, 08 Aug 2018)");
  script_name("Hughes Broadband Satellite Modems Remote Detection");

  script_tag(name:"summary", value:"Detection of presence of Hughes Broadband
  Satellite Modem.

  The script attempts to determine if the remote host runs Hughes Broadband
  Satellite Modem from the telnet banner response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://www.hughes.com/technologies/broadband-satellite-systems/hn-systems");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 1953);
  script_mandatory_keys("telnet/hughes_network_systems/broadband_satellite_modem/detected");

  exit(0);
}

include("telnet_func.inc");
include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");

modPort = telnet_get_port(default:1953);
if(!banner = telnet_get_banner(port:modPort))
  exit(0);

if("Broadband Satellite" >< banner && "Hughes Network Systems" >< banner)
{
  version = "unknown";
  install = modPort + "/tcp";
  model = eregmatch(pattern:"Broadband Satellite ([0-9A-Za-z/]+)", string:banner);
  if(model[1]){
    model = model[1];
  }

  set_kb_item(name:"hughes_broadband_satelite_modem/detected", value:TRUE);
  set_kb_item(name:"hughes_broadband_satelite_modem/model", value:model);

  cpe = "cpe:/a:hughes:broadband_satelite_modem";

  register_product(cpe:cpe, location:install, port:modPort, service:"telnet");
  log_message(data:build_detection_report(app:"Hughes Broadband Satellite Modem",
                                          version:version,
                                          install:install,
                                          cpe:cpe,
                                          concluded:"Hughes Broadband Satellite Modem Version " + version + " and Model " + model),
                                          port:modPort);
}

exit(0);
