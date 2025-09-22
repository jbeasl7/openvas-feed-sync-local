# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106098");
  script_version("2024-11-05T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-11-05 05:05:33 +0000 (Tue, 05 Nov 2024)");
  script_tag(name:"creation_date", value:"2016-06-15 17:03:46 +0700 (Wed, 15 Jun 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Siemens SIMATIC S7 Device Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Siemens SIMATIC S7 devices like S7-300
  or S7-1200 PLCs.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

url = "/Portal/Portal.mwsl?PriNav=Ident";
req = http_get(item: url, port: port);
res = http_keepalive_send_recv(port: port, data: req);

# Seen on S7-1200 / S7-1500
if ('alt="Siemens"'>< res && ('alt="Simatic Controller"></td>' >< res || 'Title_Area_Name">S7' >< res ||
                              "title>SIMATIC" >< res || 'class="s7webtable"' >< res || "S7Web.css" >< res)) {

  concluded_url = "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "siemens/simatic_s7/detected", value: TRUE);
  set_kb_item(name: "siemens/simatic_s7/http/detected", value: TRUE);
  set_kb_item(name: "siemens/simatic_s7/http/port", value: port);

  # e.g.:
  # <title>SIMATIC&nbsp;1200&nbsp;station_1</title>
  #
  # nb: Newer firmware versions have the following in the title:
  # <title>S7-1200 station_1</title>
  # but this seems to be the "Station name" which can be changed and is thus currently not used for
  # identification.
  mod = eregmatch(pattern: "<title>SIMATIC&nbsp;([A-Z]+)?([0-9]+).*</title>", string: res);
  if (!isnull(mod[2])) {
    model = mod[2];
    concluded = "    " + mod[0];
  } else {
    url = "/Portal/Portal.mwsl?PriNav=Start";

    req = http_get(port: port, item: url);
    res2 = http_keepalive_send_recv(port: port, data: req);

    # id="DISPLAY_CPU_NAME">CPU 1510SP-1 PN<
    mod = eregmatch(pattern: '"DISPLAY_CPU_NAME">CPU\\s*([^<]+)<', string: res2);
    if (!isnull(mod[1])) {
      model = mod[1];
      concluded = "    " + mod[0];
      concluded_url += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
    }
  }

  version = "unknown";
  x = 0;
  lines = split(res);

  foreach line (lines) {
    if ("Firmware:" >< line ) {
      # >V 03.00.02<
      ver = eregmatch(pattern: ">V.([^<]+)<", string: lines[x+1]);
      if (!isnull(ver[1])) {
        version = ver[1];
        if (concluded)
          concluded += '\n';
        concluded += "    " + ver[0];
        break;
      } else {
        # >V 03.00.02<
        ver = eregmatch(pattern: ">V.([^<]+)<", string: lines[x+5]);
        if (!isnull(ver[1])) {
          version = ver[1];
          if (concluded)
            concluded += '\n';
          concluded += "    " + ver[0];
          break;
        }
      }
    }
    x++;
  }

  x = 0;
  foreach line (lines) {
    if ("Order number" >< line) {
      # >6ES7 214-1AG31-0XB0<
      module = eregmatch(pattern: ">([^<]+)<", string: lines[x+1]);
      if (!isnull(module[1])) {
        set_kb_item(name: "siemens/simatic_s7/http/module", value: module[1]);
        if (concluded)
          concluded += '\n';
        concluded += "    " + module[0];
        break;
      }
    }
    x++;
  }

  module_type = eregmatch(pattern: 'moduleType">([^<]+)', string: res);
  if (!isnull(module_type[1])) {
    if (concluded)
      concluded += '\n';
    concluded += "    " + module_type[0];
    set_kb_item(name: "siemens/simatic_s7/http/modtype", value: module_type[1]);
  }

  if (concluded)
    set_kb_item(name: "siemens/simatic_s7/http/" + port + "/concluded", value: concluded);

  if (concluded_url)
    set_kb_item(name: "siemens/simatic_s7/http/" + port + "/concludedurl", value: concluded_url);

  if (model)
    set_kb_item(name: "siemens/simatic_s7/http/model", value: model);

  if (version != "unknown")
    set_kb_item(name: "siemens/simatic_s7/http/" + port + "/version", value: version);
}

# Seen on S7-300
res = http_get_cache(item: "/", port: port);
if (!res || res !~ "^HTTP/1\.[01] 302" || res !~ "Location\s*:\s*/Portal0000\.htm")
  exit(0);

url = "/Portal0000.htm";
res = http_get_cache(item: url, port: port);
if (!res || res !~ "^HTTP/1\.[01] 200")
  exit(0);

# nb: Similar to the S7-1200 devices there a few have the default of:
# <title>
# SIMATIC 300
# </title>
# but this is again the "Station name" which can be changed / modified and thus not used for
# identification.
if ('href="/S7Web.css">' >< res ||
    'alt="Simatic S7 CP">' >< res ||
    'src="/Siemens_Firmenmarke_Header.gif" alt="Siemens"' >< res) {

  set_kb_item(name: "siemens/simatic_s7/detected", value: TRUE);
  set_kb_item(name: "siemens/simatic_s7/http/detected", value: TRUE);
  set_kb_item(name: "siemens/simatic_s7/http/port", value: port);

  # Module type is directly available on Portal0000.htm like e.g.:
  #
  # <td class="static_field">Module type:</td>
  # <td class="output_field_long">CP 343-1 Lean</td>
  #
  # or:
  #
  # <td class="static_field">Module type:</td>
  # <td class="output_field_long">CP 343-1</td>
  #
  mod_type = eregmatch(pattern: ">Module type:</td>[^/]+>(CP [^<]+)</td>", string: res);
  if (!isnull(mod_type[1])) {

    module_type = mod_type[1];

    # nb: Four spaces for the reporting in the consolidation...
    concluded = "    " + str_replace(string: mod_type[0], find: '\r\n', replace: "newline-replaced");
    concluded_url = "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

    set_kb_item(name: "siemens/simatic_s7/http/modtype", value: module_type);

    # The model / series wasn't available on at least S7-300 devices so we're grabbing it from the
    # module type (if available).
    if (module_type =~ "CP 15[0-9]+")
      model = "1500";
    else if (module_type =~ "CP 12[0-9]+")
      model = "1200";
    else if (module_type =~ "CP 4[0-9]+")
      model = "400";
    else if (module_type =~ "CP 3[0-9]+")
      model = "300";
    else if (module_type =~ "CP 2[0-9]+")
      model = "200";
  }

  version = "unknown";
  # Version needs to be grabbed from the Portal1000.htm (at least on the S7-300)
  url = "/Portal1000.htm";
  res = http_get_cache(item: url, port: port);
  if (res && res =~ "^HTTP/1\.[01] 200") {

    # e.g. on the S7-300:
    #
    # <td class="static_field">Firmware:</td>
    # <td class="output_field_long">V2.3.2</td>
    #
    # or:
    #
    # <td class="static_field">Firmware:</td>
    # <td class="output_field_long">V3.1.1</td>
    #
    vers = eregmatch(pattern: ">Firmware:</td>[^/]+>V([0-9.]+)[^<]*</td>", string: res);
    if (vers[1]) {

      version = vers[1];

      if (concluded)
        concluded += '\n';
      concluded += "    " + str_replace(string: vers[0], find:'\r\n', replace: "newline-replaced");

      if (concluded_url)
        concluded_url += '\n';
      concluded_url += "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);
    }

    if (!module[1]) {

      # <td class="output_field_long">6GK7 343-1CX10-0XE0<
      module2 = eregmatch(pattern: '<td class="output_field_long">([0-9A-Z]+ [0-9A-Z-]+)[^<]*<', string: res);

      if (module2[1]) {
        set_kb_item(name: "siemens/simatic_s7/http/module", value: module2[1]);

        if (concluded)
          concluded += '\n';
        concluded += "    " + str_replace(string: module2[0], find: '\r\n', replace: "newline-replaced");

        # nb: Only add the URL if not already added previously
        if (url >!< concluded_url) {
          if (concluded_url)
            concluded_url += '\n';
          concluded_url += "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);
        }
      }
    }
  }

  if (concluded)
    set_kb_item(name: "siemens/simatic_s7/http/" + port + "/concluded", value: concluded);

  if (concluded_url)
    set_kb_item(name: "siemens/simatic_s7/http/" + port + "/concludedurl", value: concluded_url);

  if (model)
    set_kb_item(name: "siemens/simatic_s7/http/model", value: model);

  if (version != "unknown")
    set_kb_item(name: "siemens/simatic_s7/http/" + port + "/version", value: version);
}



exit(0);
