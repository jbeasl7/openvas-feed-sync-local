# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107236");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-09-08 16:22:38 +0700 (Fri, 08 Sep 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("A2billing Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.asterisk2billing.org/");

  script_tag(name:"summary", value:"Detection of A2billing.

  The script sends a connection request to the server and attempts to detect A2billing and to
  extract its version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default: 443);
rootInstalled = FALSE;

foreach dir (make_list_unique("/", "/admin", "/admin/Public", "/Public", "/a2billing", "/a2billing/Public",
                              "/a2billing/admin/Public", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/") dir = "";
  if (rootInstalled) break;

  url = dir + "/index.php";
  res = http_get_cache(port: port, item: url);

  if (res =~ "^HTTP/1\.[01] 200" && "<title>..:: A2Billing Portal ::..</title>" >< res) {

    if (install == "/") rootInstalled = TRUE;

    version = "unknown";
    ver = eregmatch( pattern: 'A2Billing v([0-9.]+) is a <a href="', string: res);

    if (!isnull(ver[1])) {
      version = ver[1];
      set_kb_item(name: "a2billing/version", value: version);
    }

    set_kb_item(name: "a2billing/installed", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:a2billing:a2billing:");
    if (!cpe)
      cpe = 'cpe:/a:a2billing:a2billing';

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "A2billing", version: version, install: install,
                                           cpe: cpe, concluded: ver[0]),
                port: port);
  }
}

exit(0);
