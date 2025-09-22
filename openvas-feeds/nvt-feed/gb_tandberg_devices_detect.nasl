# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103694");
  script_version("2025-04-11T15:45:04+0000");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2013-04-11 09:34:17 +0200 (Thu, 11 Apr 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Tandberg Devices Detection (Telnet)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/tandberg/device/detected");

  script_tag(name:"summary", value:"Telnet based detection of Tandberg Devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("telnet_func.inc");
include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");
include("cpe.inc");
include("os_func.inc");

port = telnet_get_port(default:23);

if(!banner = telnet_get_banner(port:port))
  exit(0);

if(!concl = egrep(string:banner, pattern:"TANDBERG Codec Release", icase:TRUE))
  exit(0);

set_kb_item(name:"tandberg/device/detected", value:TRUE);
set_kb_item(name:"tandberg/device/telnet/detected", value:TRUE);

concluded = chomp(concl);

version = "unknown";
install = port + "/tcp";

# TANDBERG Codec Release F9.0 NTSC
# TANDBERG Codec Release F8.2 NTSC
# TANDBERG Codec Release F7.2 NTSC
# TANDBERG Codec Release F9.1.1 PAL
# TANDBERG Codec Release F6.3 PAL

# nb: This is not the device version
vers = eregmatch(string:banner, pattern:'TANDBERG Codec Release ([^\r\n]+)', icase:TRUE);
if(!isnull(vers[1])) {
  version = vers[1];
  concluded = vers[0];
}

app_cpe = build_cpe(value:tolower(version), exp:"^([a-z0-9.]+)", base:"cpe:/a:tandberg:codec:");
if(!app_cpe)
  app_cpe = "cpe:/a:tandberg:codec";

# We don't know which device exactly it is, so just set the base CPE for both
hw_cpe = "cpe:/h:tandberg:device";
os_cpe = "cpe:/o:tandberg:device_firmware";

register_product(cpe:hw_cpe, location:install, port:port, service:"telnet");
register_product(cpe:app_cpe, location:install, port:port, service:"telnet");
register_product(cpe:os_cpe, location:install, port:port, service:"telnet");

os_register_and_report(os:"Tandberg Device Firmware", cpe:os_cpe, banner_type:"Telnet login", banner:concluded, desc:"Tandberg Devices Detection (Telnet)", runs_key:"unixoide");

report  = build_detection_report(app:"Tandberg Device", skip_version:TRUE, install:install, cpe:hw_cpe);
report += '\n\n';
report += build_detection_report(app:"Tandberg Device Firmware", skip_version:TRUE, install:install, cpe:os_cpe);
report += '\n\n';
report += build_detection_report(app:"Tandberg Codec", version:version, install:install, cpe:app_cpe);
report += '\n\n';
report += 'Concluded from version/product identification result:\n\n' + concluded;

log_message(port:port, data:report);

exit(0);
