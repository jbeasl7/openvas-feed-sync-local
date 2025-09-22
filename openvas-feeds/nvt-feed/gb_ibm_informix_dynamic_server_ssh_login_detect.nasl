# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902547");
  script_version("2025-07-08T05:41:10+0000");
  script_tag(name:"last_modification", value:"2025-07-08 05:41:10 +0000 (Tue, 08 Jul 2025)");
  script_tag(name:"creation_date", value:"2011-08-02 09:08:31 +0200 (Tue, 02 Aug 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("IBM Informix Dynamic Server Detection (Linux/Unix SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of IBM Informix Dynamic Server.");

  script_xref(name:"URL", value:"https://www.ibm.com/products/informix");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("ssh_func.inc");

if (!soc = ssh_login_or_reuse_connection())
  exit(0);

port = kb_ssh_transport();

paths = ssh_find_bin(sock: soc, prog_name: "oninit");

foreach bin (paths) {
  bin = chomp(bin);
  if (!bin)
    continue;

  # IBM Informix Dynamic Server Version 15.0.0.1DE
  vers = ssh_get_bin_version(full_prog_name: bin, sock: soc, version_argv: "-V",
                             ver_pattern:"IBM Informix Dynamic Server Version ([0-9.]+)");

  if (!vers || isnull(vers[1]))
    continue;

  version = vers[1];

  set_kb_item(name: "ibm/informix/dynamic_server/detected", value: TRUE);
  set_kb_item(name: "ibm/informix/dynamic_server/ssh-login/detected", value: TRUE);

  cpe = build_cpe(value: vers[1], exp: "^([0-9.]+)", base: "cpe:/a:ibm:informix_dynamic_server:");
  if (!cpe)
    cpe = "cpe:/a:ibm:informix_dynamic_server";

  register_product(cpe: cpe, location: bin, port: port, service: "ssh-login");

  log_message(data: build_detection_report(app: "IBM Informix Dynamic Server", version: version,
                                           install: bin, cpe: cpe, concluded:vers[0]),
              port: port);
}

exit(0);
