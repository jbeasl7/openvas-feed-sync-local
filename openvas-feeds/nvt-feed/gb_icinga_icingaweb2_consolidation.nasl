# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170047");
  script_version("2025-05-06T05:40:10+0000");
  script_tag(name:"last_modification", value:"2025-05-06 05:40:10 +0000 (Tue, 06 May 2025)");
  script_tag(name:"creation_date", value:"2022-03-17 20:22:51 +0000 (Thu, 17 Mar 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Icinga Web 2 Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_icinga_icingaweb2_ssh_login_detect.nasl",
                      "sw_icingaweb2_http_detect.nasl");
  script_mandatory_keys("icinga/icingaweb2/detected");

  script_tag(name:"summary", value:"Consolidation of Icinga Web 2 detections.");

  script_xref(name:"URL", value:"https://icinga.com/docs/icinga-web-2/latest/doc/01-About/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

if (!get_kb_item("icinga/icingaweb2/detected"))
  exit(0);

report = ""; # nb: To make openvas-nasl-lint happy...

foreach source (make_list("http", "ssh-login")) {

  install_list = get_kb_list("icinga/icingaweb2/" + source + "/*/installs");

  if (!install_list)
    continue;

  install_list = sort(install_list);

  foreach install (install_list) {
    infos = split(install, sep:"#---#", keep:FALSE);
    if (max_index(infos) < 3)
      continue; # Something went wrong and not all required infos are there...

    port     = infos[0];
    install  = infos[1];
    version  = infos[2];
    concl    = infos[3];
    conclurl = infos[4];

    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:icinga:icingaweb2:");
    if (!cpe)
      cpe = "cpe:/a:icinga:icingaweb2";

    if (source == "http")
      source = "www";

    register_product(cpe:cpe, location:install, port:port, service:source);

    if (report)
      report += '\n\n';

    report += build_detection_report(app:"Icinga Web 2", version:version, install:install, cpe:cpe,
                                     concluded:concl, concludedUrl:conclurl);
  }
}

log_message(port:0, data:chomp(report));

exit(0);
