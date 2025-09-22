# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102101");
  script_version("2025-08-28T05:39:05+0000");
  script_tag(name:"last_modification", value:"2025-08-28 05:39:05 +0000 (Thu, 28 Aug 2025)");
  script_tag(name:"creation_date", value:"2024-09-25 10:19:46 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Oracle Database Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Product detection");
  script_dependencies("oracle_tnslsnr_version.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_oracle_database_smb_login_detect.nasl",
                        "gsf/gb_oracle_database_ssh_login_detect.nasl");
  script_mandatory_keys("oracle/database/detected");

  script_tag(name:"summary", value:"Consolidation of Oracle Database detections.");

  script_xref(name:"URL", value:"https://www.oracle.com/database/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

if (!get_kb_item("oracle/database/detected"))
  exit(0);

report = ""; # nb: To make openvas-nasl-lint happy...

foreach source (make_list("ssh-login", "smb-login", "tnslsnr")) {
  install_list = get_kb_list("oracle/database/" + source + "/*/installs");
  if (!install_list)
    continue;

  install_list = sort(install_list);

  foreach install (install_list) {
    infos = split(install, sep: "#---#", keep: FALSE);
    if (max_index(infos) < 3)
      continue; # Something went wrong and not all required infos are there...

    port     = infos[0];
    install  = infos[1];
    version  = infos[2];
    concl    = infos[3];
    extra    = infos[4];
    conclurl = infos[5];

    cpe = build_cpe(value: version, exp: "^([0-9a-z.]+)", base: "cpe:/a:oracle:database_server:");
    if (!cpe)
      cpe = "cpe:/a:oracle:database_server";

    register_product(cpe: cpe, location: install, port: port, service: source);

    if (report)
      report += '\n\n';

    report += build_detection_report(app: "Oracle Database", version: version, install: install, cpe: cpe,
                                     concluded: concl, concludedUrl: conclurl, extra: extra);
  }
}

if (report)
  log_message(port: 0, data: report);

exit(0);
