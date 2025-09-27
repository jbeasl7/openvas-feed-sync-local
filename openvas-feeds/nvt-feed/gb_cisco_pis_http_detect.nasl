# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105613");
  script_version("2025-09-26T15:41:32+0000");
  script_tag(name:"last_modification", value:"2025-09-26 15:41:32 +0000 (Fri, 26 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-04-20 16:20:47 +0200 (Wed, 20 Apr 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco Prime Infrastructure (PIS) Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Cisco Prime Infrastructure (PIS).");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default: 443);

url = "/webacs/pages/common/login.jsp";

res = http_get_cache(port: port, item: url);

if (res =~ "^HTTP/1\.[01] 200" && "Prime Infrastructure" >< res && "Cisco" >< res) {
  version = "unknown";
  conclUrl = "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "cisco/pis/detected", value: TRUE);
  set_kb_item(name: "cisco/pis/http/detected", value: TRUE);
  set_kb_item(name: "cisco/pis/http/port", value: port);

  url = "/webacs/pages/common/updateQuickView.jsp";

  req = http_get(port: port, item: url);
  res2 = http_keepalive_send_recv(port: port, data: req);

  if ("Critical Fixes" >< res2) {
    lines = split(res2);
    foreach line (lines) {
      if (line =~ 'var arr.*"Critical Fixes"') {
        if ('"id"' >< line)
          sep = '"id"';
        else
          sep = '"description"';

        ids = split(line, sep: sep, keep: TRUE);
        foreach id (ids) {
          if ("TECH PACK" >< id)
            continue;
          patch = eregmatch(pattern: '"name":"PI ([0-9]+\\.[^"]+)"', string: id);
          if (!isnull(patch[1]))
              installed_patches += "    " + patch[1] + '\n';
        }
        break;
      }
    }
  }

  if (installed_patches) {
    conclUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
    patches = split(installed_patches, keep: FALSE);
    foreach patch (patches) {
      patch = ereg_replace(pattern: '^\\s*', string: patch, replace: "");
      if ("Update" >< patch || patch =~ "[a-zA-Z ]+") {
        p = eregmatch(pattern: "(^[0-9.]+)", string: patch);
        if (!isnull(p[1]))
          patch = p[1];
      }

      if (!max_patch_version)
        max_patch_version = patch;
      else
        if (version_is_less(version: max_patch_version, test_version: patch))
          max_patch_version = patch;
    }

    set_kb_item( name:"cisco/pis/http/" + port + "/max_patch_version", value: max_patch_version);
    version = chomp(max_patch_version);
    conclUurl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
  } else {
    installed_patches = "unknown";
  }

  # First check location for newer versions (see comment in the next check below)
  if (version == "unknown") {
    url = "/webacs/js/xmp/nls/xmp.js";

    req = http_get(port: port, item: url);
    res3 = http_keepalive_send_recv(port: port, data: req);

    # file_version: "Version: 3.0",
    vers = eregmatch(pattern: 'file_version\\s*:\\s*"Version\\s*:\\s*([0-9.]+)",', string: res3);
    if (!isnull(vers[1])) {
      version = vers[1];
      set_kb_item(name: "cisco/pis/http/" + port + "/concluded", value: vers[0]);
      conclUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
    }
  }

  if (version == "unknown") {
    # nb: Newer versions of PIS (e.g. 3.0.0) have commented out that one
    # like // dojo.query(".productVersion")[0].innerHTML= "Version: 2.2";
    vers = eregmatch(pattern: '[^/]*dojo\\.query\\("\\.productVersion"\\)\\[0\\]\\.innerHTML= .Version: ([0-9.]+[^\'"]+).;',
                     string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      set_kb_item(name: "cisco/pis/http/" + port + "/concluded", value: vers[0]);
    }
  }

  set_kb_item(name: "cisco/pis/http/" + port + "/version", value: version);
  set_kb_item(name: "cisco/pis/http/" + port + "/concludedUrl", value: conclUrl);
  set_kb_item(name: "cisco/pis/http/" + port + "/installed_patches", value: chomp(installed_patches));
}

exit(0);
