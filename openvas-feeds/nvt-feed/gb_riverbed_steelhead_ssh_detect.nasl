# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106845");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-06-02 13:17:40 +0700 (Fri, 02 Jun 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Riverbed SteelHead Detection (SSH)");

  script_tag(name:"summary", value:"Detection of Riverbed SteelHead.

  The script tries to log in to Riverbed SteelHead and execute 'show version' command to extract its version and
  model.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/riverbed/steelhead/detected");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ssh_get_port(default:22);
banner = ssh_get_login_banner(port:port);
if (!banner || "Riverbed SteelHead" >!< banner)
  exit(0);

set_kb_item(name: "riverbed/steelhead/detected", value: TRUE);

version = "unknown";
report_app = "Riverbed SteelHead";

soc = ssh_login_or_reuse_connection();
if (soc) {
  # pty has to set to TRUE otherwise we will get 'Riverbed ssh: ssh remote command is not allowed'
  sysversion = ssh_cmd(socket: soc, cmd: 'show version', pty: TRUE, nosh: TRUE);

  mod = eregmatch(pattern: "Product model:     ([^ ]+)", string: sysversion);
  if (!isnull(mod[1])) {
    model = mod[1];
    report_app += ' ' + model;
    replace_kb_item(name: "riverbed/steelhead/model", value: model);
  }

  vers = eregmatch(pattern: "Product release:   ([0-9a-z.]+)", string: sysversion);
  if (!isnull(vers[1])) {
    version = vers[1];
    replace_kb_item(name: "riverbed/steelhead/version", value: version);
  }
}

cpe = build_cpe(value: version, exp: "^([0-9][0-9a-z.]+)", base: "cpe:/a:riverbed:steelhead:");
if (!cpe)
  cpe = 'cpe:/a:riverbed:steelhead';

os_register_and_report(os: "Riverbed Optimization System (RiOS)", cpe: "cpe:/o:riverbed:riverbed_optimization_system", desc: "Riverbed SteelHead Detection (SSH)", runs_key: "unixoide");

register_product(cpe: cpe, location: port + "/tcp", port: port, service: "ssh");

log_message(data: build_detection_report(app: report_app, version: version, install: port + "/tcp", cpe: cpe),
            port: port);

exit(0);
