# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106384");
  script_version("2025-03-26T05:38:58+0000");
  script_tag(name:"last_modification", value:"2025-03-26 05:38:58 +0000 (Wed, 26 Mar 2025)");
  script_tag(name:"creation_date", value:"2016-11-29 08:20:28 +0700 (Tue, 29 Nov 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Foreman Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Foreman.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://theforeman.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/users/login";

res = http_get_cache(port: port, item: url);

if ((concl = egrep(pattern: '(Welcome to Foreman|foreman-react-component name="LoginPage")', string: res, icase: TRUE)) &&
     ("<title>Login</title>" >< res)) {
  version = "unknown";
  concluded = "  " + chomp(concl);
  concludedurl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  # nb: Red Hat Satellite is detected via another detection
  if (egrep(pattern: '(<body class="pf-m-redhat-font satellite-theme">|Red Hat Satellite)', string: res, icase: TRUE))
    exit(0);

  set_kb_item(name: "foreman/detected", value: TRUE);

  # id="version">Version 1.19.1
  vers = eregmatch(pattern: 'id="version">Version ([0-9.]+)', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concluded += '\n  ' + vers[0];
  }
  else {
    # <p>Version 1.7.3
    vers = eregmatch(pattern: "<p>Version ([0-9.]+)", string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      concluded += '\n  ' + vers[0];
    } else {
      # &quot;Version 3.14.0&quot;
      # &quot;version&quot;:&quot;2.3.5&quot;
      vers = eregmatch(pattern: "&quot;[Vv]ersion( |&quot;:&quot;)([.0-9]+(-rc[0-9]+)?)&quot;", string: res);
      if (!isnull(vers[2])) {
        version = vers[2];
        concluded += '\n  ' + vers[0];
      }
    }
  }

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:theforeman:foreman:");
  if (!cpe)
    cpe = "cpe:/a:theforeman:foreman";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Foreman", version: version,
                                           install: "/", cpe: cpe,
                                           concluded: concluded, concludedUrl: concludedurl),
              port: port);
  exit(0);
}

exit(0);
