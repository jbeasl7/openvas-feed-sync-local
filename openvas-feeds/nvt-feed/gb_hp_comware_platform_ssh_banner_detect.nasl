# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106411");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-11-25 11:50:20 +0700 (Fri, 25 Nov 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("HP Comware Devices Detect (SSH Banner)");

  script_tag(name:"summary", value:"SSH banner-based detection of HP Comware Devices.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/hp/comware/detected");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ssh_get_port(default:22);
banner = ssh_get_serverbanner(port:port);
if (!banner || banner !~ "SSH-[0-9.]+-Comware")
  exit(0);

version = "unknown";

vers = eregmatch(pattern: "Comware-([0-9.]+)", string: banner);
if (!isnull(vers[1])) {
  version = vers[1];
  set_kb_item(name: "hp/comware_device/version", value: version);
}

set_kb_item(name: "hp/comware_device", value: TRUE);

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:hp:comware:");
if (!cpe)
  cpe = "cpe:/a:hp:comware";

register_product(cpe: cpe, port: port, service: "ssh");

log_message(data: build_detection_report(app: "HP Comware Device", version: version, cpe: cpe, concluded: vers[0]),
            port: port);

exit(0);
