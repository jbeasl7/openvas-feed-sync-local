# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140334");
  script_version("2024-06-17T08:31:37+0000");
  script_tag(name:"last_modification", value:"2024-06-17 08:31:37 +0000 (Mon, 17 Jun 2024)");
  script_tag(name:"creation_date", value:"2017-08-30 08:37:15 +0700 (Wed, 30 Aug 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("FreeIPA Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of FreeIPA.");

  script_xref(name:"URL", value:"https://www.freeipa.org");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/ipa/ui/";

res = http_get_cache(port: port, item: url);

if ("<title>IPA: Identity Policy Audit</title>" >< res && "freeipa/app" >< res) {
  version = "unknown";
  location = "/ipa";
  concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "freeipa/detected", value: TRUE);
  set_kb_item(name: "freeipa/http/detected", value: TRUE);

  url = "/ipa/ui/js/libs/loader.js";

  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  # num_version: '40404' for version 4.4.4
  vers = eregmatch(pattern: "num_version\s*:\s*'([0-9]+)'", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    if (strlen(version) == 5) {
      v1 = version[0];
      v2 = ereg_replace(string: substr(version, 1, 2), pattern: "^0", replace: "");
      v3 = ereg_replace(string: substr(version, 3, 4), pattern: "^0", replace: "");
      version = v1 + "." + v2 + "." + v3;
    }
    concUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:freeipa:freeipa:");
  if (!cpe)
    cpe = "cpe:/a:freeipa:freeipa";

  register_product(cpe: cpe, location: location, port: port, service: "www");

  os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", port: port, runs_key: "unixoide",
                         desc: "FreeIPA Detection (HTTP)");

  log_message(data: build_detection_report(app: "FreeIPA", version: version, install: location, cpe: cpe,
                                           concluded: vers[0], concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
