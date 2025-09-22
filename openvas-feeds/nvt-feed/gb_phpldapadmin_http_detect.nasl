# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100395");
  script_version("2024-12-24T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-12-24 05:05:31 +0000 (Tue, 24 Dec 2024)");
  script_tag(name:"creation_date", value:"2009-12-15 19:11:56 +0100 (Tue, 15 Dec 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("phpLDAPadmin Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of phpLDAPadmin.");

  script_xref(name:"URL", value:"https://github.com/leenooks/phpLDAPadmin");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/phpldapadmin", "/ldapadmin", "/ldap", "/phpldapadmin/htdocs",
                              "/ldapadmin/htdocs", "/htdocs", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/index.php";
  res = http_get_cache(port: port, item: url);
  if (!res)
    continue;

  if ("<title>phpLDAPadmin" >< res && ("phpLDAPadmin logo" >< res || 'src="tree.php"' >< res ||
      'src="welcome.php"' >< res)) {
    version = "unknown";
    conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

    # <title>phpLDAPadmin (1.2.2) - </title>
    vers = eregmatch(pattern: "phpLDAPadmin \(([0-9.]+)\)", string: res, icase: TRUE);
    if (!isnull(vers[1]))
      version = vers[1];

    if (version == "unknown") {
      # <title>phpLDAPadmin - 0.9.5
      # <title>phpLDAPadmin - 0.9.4b
      vers = eregmatch(pattern: "<title>phpLDAPadmin - ([0-9a-z.]+)", string: res, icase: TRUE);
      if (!isnull(vers[1]))
        version = vers[1];
    }

    set_kb_item(name: "phpldapadmin/detected", value: TRUE);
    set_kb_item(name: "phpldapadmin/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9a-z.]+)", base: "cpe:/a:phpldapadmin_project:phpldapadmin:");
    if (!cpe)
      cpe = "cpe:/a:phpldapadmin_project:phpldapadmin";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "phpLDAPadmin", version: version, install: install,
                                             cpe: cpe, concluded: vers[0], concludedUrl: conclUrl),
                port: port);
  }
}

exit(0);
