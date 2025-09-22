# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107218");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-06-12 06:40:16 +0200 (Mon, 12 Jun 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Evolution Script CMS Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of Evolution Script CMS.

  The script tries to detect the version of Evolution Script CMS remote host and sets the KB entries.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

appPort = http_get_port(default: 80);

foreach dir( make_list_unique( "/admin", http_cgi_dirs( port: appPort ) ) ) {

  install = dir;
  if (dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/" , port: appPort);

  if (rcvRes =~ "^HTTP/1\.[01] 200" && "<title>EvolutionScript - Login</title>" >< rcvRes ) {

    Ver = "unknown";

    tmpVer = eregmatch(pattern: "EvolutionScript ([0-9.]+) Admin Control Panel", string: rcvRes);

    if(tmpVer[1]) {
      Ver = tmpVer[1];
    }

    set_kb_item(name: "evolution_script/installed", value: TRUE);
    set_kb_item(name: "evolution_script/version", value: Ver);


    cpe = build_cpe(value: Ver, exp: "^([0-9.]+)", base:"cpe:/a:evolutionscript:evolutionscript:");

    if(!cpe)
      cpe = 'cpe:/a:evolutionscript:evolutionscript';

    register_product(cpe: cpe, location: install, port: appPort, service: "www");

    log_message(data:build_detection_report(app: "Evolution Script CMS",
                                            version: Ver,
                                            install: install,
                                            cpe: cpe,
                                            concluded: tmpVer[0]),
                                            port: appPort);
  }
}

exit(0);
