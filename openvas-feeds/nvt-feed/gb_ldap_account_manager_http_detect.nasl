# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103158");
  script_version("2024-03-22T15:42:29+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-03-22 15:42:29 +0000 (Fri, 22 Mar 2024)");
  script_tag(name:"creation_date", value:"2011-05-03 13:15:04 +0200 (Tue, 03 May 2011)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("LDAP Account Manager Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8181);
  script_mandatory_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of LDAP Account Manager.");

  script_xref(name:"URL", value:"https://www.ldap-account-manager.org/lamcms/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 8181);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/ldap", "/ldap-account-manager", "/lam", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  # nb: Some systems requires to access the URL with a trailing "/"
  foreach suffix (make_list("", "/")) {
    url = dir + "/templates/login.php" + suffix;
    res = http_get_cache(port: port, item: url);
    if (res =~ "^HTTP/1\.[01] 200")
      break;
  }

  if (!res)
    continue;

  if ("<title>LDAP Account Manager</title>" >< res && "lam" >< res) {
    version = "unknown";
    concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

    # nb: These have tabs instead of spaces
    # LDAP Account Manager - 4.4
    # LDAP Account Manager Pro - 8.0.1
    # LDAP Account Manager - 8.0.1                </span>
    # LDAP Account Manager - 5.5&nbsp;&nbsp;&nbsp;          </SMALL>
    # LDAP Account Manager - 4.4&nbsp;&nbsp;&nbsp;          </SMALL>
    # LDAP Account Manager - 7.3          </a>
    # LDAP Account Manager - 8.6                </span>
    vers  = eregmatch(string: res, pattern: "LDAP Account Manager( Pro)? - ([0-9.]+)", icase: TRUE);
    if (!isnull(vers[2]))
      version = vers[2];

    set_kb_item(name: "ldap_account_manager/detected", value: TRUE);
    set_kb_item(name: "ldap_account_manager/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:ldap-account-manager:ldap_account_manager:");
    if (!cpe)
      cpe = "cpe:/a:ldap-account-manager:ldap_account_manager";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "LDAP Account Manager", version: version, install: install,
                                             cpe: cpe, concluded: vers[0], concludedUrl: concUrl),
                port: port);
    exit(0);
  }
}

exit(0);
