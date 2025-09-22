# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106548");
  script_version("2024-06-05T05:05:26+0000");
  script_tag(name:"last_modification", value:"2024-06-05 05:05:26 +0000 (Wed, 05 Jun 2024)");
  script_tag(name:"creation_date", value:"2017-01-30 10:52:02 +0700 (Mon, 30 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Dell Data Protection Advisor (DPA) Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9002);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Dell Data Protection Advisor (DPA).");

  script_xref(name:"URL", value:"https://www.dell.com/en-us/dt/data-protection/data-protection-suite/data-protection-advisor.htm");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 9002);

url = "/";
found = 0;

res = http_get_cache(port: port, item: url);

# nb: First two are from older systems / versions not found anymore.

# <title>Data Protection Advisor</title>
if (concl = eregmatch(string: res, pattern: "<title>Data Protection Advisor</title>", icase: FALSE)) {
  found++;
  concluded = "  " + concl[0];
}

if (concl = eregmatch(string: res, pattern: 'description">Server is starting\\. Please wait\\.', icase: FALSE)) {
  found++;
  if (concluded)
    concluded += '\n';
  concluded += "  " + concl[0];
}

# <h1>Data Protection Advisor</h1>
if (concl = eregmatch(string: res, pattern: "<h[0-9]+>Data Protection Advisor</h[0-9]+>", icase: FALSE)) {
  found++;
  if (concluded)
    concluded += '\n';
  concluded += "  " + concl[0];
}

if (concl = eregmatch(string: res, pattern: "<title>DPA</title>", icase: FALSE)) {
  found++;
  if (concluded)
    concluded += '\n';
  concluded += "  " + concl[0];
}

if (found > 1) {
  version = "unknown";
  build = "unknown";
  location = "/";
  conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "dell/dpa/detected", value: TRUE);
  set_kb_item(name: "dell/dpa/http/detected", value: TRUE);

  vers = eregmatch(pattern: 'var version = "([0-9.]+)[^"]*"', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concluded += '\n  ' + vers[0];

    bld = eregmatch(pattern: 'var buildNumber = "([0-9]+)[^"]*"', string: res);
    if (!isnull(bld[1])) {
      build = bld[1];
      set_kb_item(name: "dell/dpa/build", value: build);
      concluded += '\n  ' + bld[0];
    }
  } else {
    url = "/dpa-api/server/startup-status";

    req = http_get(port: port, item: url);
    res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

    major = eregmatch(pattern: "<major>([0-9]+)[^<]*</major>", string: res);
    if (!isnull(major[1])) {
      version = major[1];
      concluded += '\n  ' + major[0];
      conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);

      minor = eregmatch(pattern: "<minor>([0-9]+)[^<]*</minor>", string: res);
      if (!isnull(minor[1])) {
        version += "." + minor[1];
        concluded += '\n  ' + minor[0];
      }
    }

    bld = eregmatch(pattern: "<build>([0-9]+)[^<]*</build>", string: res);
    if (!isnull(bld[1])) {
      build = bld[1];
      set_kb_item(name: "dell/dpa/build", value: build);
      concluded += '\n  ' + bld[0];
    }

    # nb: There is also a <maintenance>0</maintenance> but this seems to be usually 0 (might be a
    # "maintenance" mode or similar).
  }

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:dell:emc_data_protection_advisor:");
  if (!cpe)
    cpe = "cpe:/a:dell:emc_data_protection_advisor";

  register_product(cpe: cpe, location: location, port: port, service: "www");

  log_message(data: build_detection_report(app: "Dell Data Protection Advisor (DPA)", version: version,
                                           build: build, install: location, cpe: cpe, concluded: concluded,
                                           concludedUrl: conclUrl),
              port: port);
  exit(0);
}

exit(0);
