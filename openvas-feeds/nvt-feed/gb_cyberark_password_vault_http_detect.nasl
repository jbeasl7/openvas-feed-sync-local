# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140960");
  script_version("2025-03-07T05:38:18+0000");
  script_tag(name:"last_modification", value:"2025-03-07 05:38:18 +0000 (Fri, 07 Mar 2025)");
  script_tag(name:"creation_date", value:"2018-04-12 14:10:27 +0700 (Thu, 12 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("CyberArk Password Vault Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of CyberArk Password Vault.");

  script_xref(name:"URL", value:"https://www.cyberark.com/products/privileged-access/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

if (!http_can_host_asp(port: port))
  exit(0);

url = "/PasswordVault/about.aspx";

res = http_get_cache(port: port, item: url);

# Password Vault seems to have a session be created first by accessing one of the locations below
if (res !~ "^HTTP/1\.[01] 302" || 'ASP.NET_SessionId=' >!< res ||
    res !~ "Location: /PasswordVault/auth/(ldap|radius|cyberark|pki)") {
  url = "/PasswordVault/v10/logon";

  res = http_get_cache(port: port, item: url);

  if ("<title>Password Vault</title>" >!< res)
    exit(0);
}

if (url == "/PasswordVault/about.aspx") {
  cookie = http_get_cookie_from_header(buf: res, pattern: "(ASP.NET_SessionId=[^;]+)");
  if (!cookie[1])
    exit(0);

  location = http_extract_location_from_redirect(port: port, data: res, current_dir: "/PasswordVault/");
  if (isnull(location))
    exit(0);

  location += "/";

  headers = make_array("Cookie", cookie);

  # Seems to essablish the session, otherwise we get another 302 response
  req = http_get_req( port: port, url: location, add_headers: headers);
  res = http_keepalive_send_recv(port: port, data: req);

  # Now we should be able to access the about page
  req = http_get_req( port: port, url: url, add_headers: headers);
  res = http_keepalive_send_recv(port: port, data: req);

  if ("CyberArk Password Vault" >!< res)
    exit(0);
}

version = "unknown";
install = "/PasswordVault";
conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

vers = eregmatch(pattern: "Version ([0-9.]+)", string: res);
if (!isnull(vers[1])) {
  version = vers[1];
} else {
  url = "/PasswordVault/api/server";

  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  vers = eregmatch(pattern: '"ExternalVersion"\\s*:\\s*"([0-9.]+)"', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }
}

set_kb_item(name: "cyberark/pwvault/detected", value: TRUE);
set_kb_item(name: "cyberark/pwvault/http/detected", value: TRUE);

os_register_and_report(os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", port: port,
                       desc: "CyberArk Password Vault Detection (HTTP)", runs_key: "windows");

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:cyberark:password_vault:");
if (!cpe)
  cpe = 'cpe:/a:cyberark:password_vault';

register_product(cpe: cpe, location: install, port: port, service: "www");

log_message(data: build_detection_report(app: "CyberArk Password Vault" , version: version,
                                         install: install, cpe: cpe, concluded: vers[0],
                                         concludedUrl: conclUrl),
            port: port);

exit(0);
