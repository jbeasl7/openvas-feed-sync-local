# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143062");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2019-11-05 04:16:35 +0000 (Tue, 05 Nov 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("rConfig Detection");

  script_tag(name:"summary", value:"Detection of rConfig.

  The script sends a connection request to the server and attempts to detect rConfig.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.rconfig.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

if (!http_can_host_php(port: port))
  exit(0);

res = http_get_cache(port: port, item: "/login.php");
if (res =~ "^HTTP/1\.[01] 302")
  res = http_get_cache(port: port, item: "/login");

if ((res =~ "Copyright \(c\)[^-]+- rConfig" && "rConfigLogo" >< res) ||
    'content="rConfig"' >< res) {
  version = "unknown";

  # rConfig Version 3.9.2
  vers = eregmatch(pattern: "rConfig Version ([0-9.]+)", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
  } else {
    # content="rConfig 5">
    vers = eregmatch(pattern: 'content="rConfig ([0-9]+)">', string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
    }
  }

  set_kb_item(name: "rconfig/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:rconfig:rconfig:");
  if (!cpe)
    cpe = "cpe:/a:rconfig:rconfig";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "rConfig", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
