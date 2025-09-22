# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171711");
  script_version("2025-09-12T15:39:53+0000");
  script_tag(name:"last_modification", value:"2025-09-12 15:39:53 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-08-28 06:30:53 +0000 (Thu, 28 Aug 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Liferay Portal/DXP Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Liferay Portal/DXP detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_liferay_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_liferay_ssh_login_detect.nasl");
  script_mandatory_keys("liferay/detected");

  script_xref(name:"URL", value:"https://www.liferay.com/");

  exit(0);
}

include("host_details.inc");
include("cpe.inc");

if (!get_kb_item("liferay/detected"))
  exit(0);

report = ""; # nb: To make openvas-nasl-lint happy...

foreach source (make_list("http", "ssh-login")) {

  install_list = get_kb_list("liferay/" + source + "/*/installs");

  if (!install_list)
    continue;

  install_list = sort(install_list);

  foreach install (install_list) {
    infos = split(install, sep:"#---#", keep:FALSE);
    if (max_index(infos) < 4)
      continue; # Something went wrong and not all required infos are there...

    port     = infos[0];
    edition  = infos[1];
    install  = infos[2];
    version  = infos[3];
    concl    = infos[4];
    conclurl = infos[5];
    extra    = infos[6];

    set_kb_item(name: "liferay/" + port + "/edition", value: edition);

    if (edition =~ "^DXP" || edition =~ "Digital Experience Platform") {
      set_kb_item(name: "liferay/dxp/detected", value: TRUE);
      set_kb_item(name: "liferay/dxp/" + source + "/detected", value: TRUE);
      cpe_version = version;
      if (version =~ "Update") {
        elements = split(version, sep:" ", keep:FALSE);
        cpe_version = elements[0] + "_" + "update" + elements[2];
      }

      cpe = build_cpe(value: tolower(cpe_version), exp: "([0-9.a-z]+)_(update[0-9]+)", base: "cpe:/a:liferay:dxp:");
      if (!cpe)
        cpe = "cpe:/a:liferay:dxp";
    } else {
      set_kb_item(name: "liferay/portal/detected", value: TRUE);
      set_kb_item(name: "liferay/portal/" + source + "/detected", value: TRUE);
      cpe = build_cpe(value: tolower(version), exp: "([0-9.a-z]+)", base: "cpe:/a:liferay:liferay_portal:");
      if(!cpe)
        cpe = "cpe:/a:liferay:liferay_portal";
    }

    if (source == "http")
      source = "www";

    register_product(cpe: cpe, location: install, port: port, service: source);

    if (report)
      report += '\n\n';

    # nb: This is needed as newer HTTP implementation / SSH-Login might only send Portal or DXP
    edition_name = edition;
    if (edition == "DXP")
      edition_name = "Digital Experience Platform";
    else if (edition == "Portal")
      edition_name = "Portal Community Edition";

    report += build_detection_report(app: "Liferay " + edition_name, version: version, install: install,
                                             cpe: cpe, concluded: concl, concludedUrl: conclurl, extra: extra);
  }
}

log_message(port:0, data:chomp(report));

exit(0);