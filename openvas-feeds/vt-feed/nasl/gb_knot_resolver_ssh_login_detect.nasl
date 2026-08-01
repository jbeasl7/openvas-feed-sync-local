# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113448");
  script_version("2026-07-28T06:26:22+0000");
  script_tag(name:"last_modification", value:"2026-07-28 06:26:22 +0000 (Tue, 28 Jul 2026)");
  script_tag(name:"creation_date", value:"2019-07-22 15:22:00 +0200 (Mon, 22 Jul 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("Knot Resolver Detection (Linux/Unix SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of Knot Resolver.");

  script_xref(name:"URL", value:"https://www.knot-resolver.cz/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("ssh_func.inc");

if (!soc = ssh_login_or_reuse_connection())
  exit(0);

# nb: [k]not [res]olver [d]aemon
files = ssh_find_file(file_name: "/kresd$", useregex: TRUE, sock: soc);

foreach bin (files) {
  if (!bin = chomp(bin))
    continue;

  vers = ssh_get_bin_version(full_prog_name: bin, version_argv: "--version", sock: soc,
                             ver_pattern: "Knot Resolver, version ([0-9.]+\.[0-9]+\.[0-9]+)[a-z0-9+.]*");
  if (!isnull(vers[1])) {
    version = vers[1];

    set_kb_item(name: "knot/resolver/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:nic:knot_resolver:");
    if (!cpe)
      cpe = "cpe:/a:nic:knot_resolver";

    register_product(cpe: cpe, location: bin, port: 0, service: "ssh-login");

    log_message(data: build_detection_report(app: "Knot Resolver", version: version, install: bin,
                                             cpe: cpe, concluded: vers[0]),
                port: 0);
  }
}

ssh_close_connection();

exit(0);
