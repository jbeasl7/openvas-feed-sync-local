# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114109");
  script_version("2024-03-06T05:05:53+0000");
  script_tag(name:"last_modification", value:"2024-03-06 05:05:53 +0000 (Wed, 06 Mar 2024)");
  script_tag(name:"creation_date", value:"2019-07-15 15:03:33 +0200 (Mon, 15 Jul 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("JetBrains TeamCity Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of JetBrains TeamCity.");

  script_xref(name:"URL", value:"https://www.jetbrains.com/teamcity/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/login.html";

res = http_get_cache(port: port, item: url);

# nb: Seen on 2023.x and 8.x:
# <meta name="application-name" content="TeamCity (Log in to TeamCity &amp;mdash; TeamCity)"/>
#
if (concl = egrep(string: res, pattern: 'content="TeamCity \\(Log in to TeamCity', icase: FALSE)) {
  found = TRUE;
  concl = ereg_replace(string: concl, pattern: "^(\s)+", replace: "");
  concluded = "  " + chomp(concl);
}

# e.g.:
#
# TeamCity-Node-Id: MAIN_SERVER
# teamcity-node-id: main
# teamcity-node-id: secondary
#
if (concl = egrep(string: res, pattern: "^[Tt]eam[Cc]ity-[Nn]ode-[Id]d\s*:.+", icase: FALSE)) {
  found = TRUE;
  if (concluded)
    concluded += '\n';
  concluded += "  " + chomp(concl);
}

# Seen on 2023.x:
# <title>Log in to TeamCity &mdash; TeamCity</title>
#
# Seen on 8.x:
# <title>Log in to TeamCity -- TeamCity</title>
#
if (concl = egrep(string: res, pattern: "<title>Log in to TeamCity (&mdash;|--) TeamCity</title>", icase: FALSE)) {
  found = TRUE;
  if (concluded)
    concluded += '\n';
  concl = ereg_replace(string: concl, pattern: "^(\s)+", replace: "");
  concluded += "  " + chomp(concl);
}

# If in "Maintenance mode" (nb: These are throwing a 503 status code)
#
# <title>TeamCity Maintenance &mdash; TeamCity</title>
#
# but probably also:
#
# <title>TeamCity Maintenance -- TeamCity</title>
if (concl = egrep(string: res, pattern: "<title>TeamCity Maintenance (&mdash;|--) TeamCity</title>", icase: FALSE)) {
  found = TRUE;
  if (concluded)
    concluded += '\n';
  concl = ereg_replace(string: concl, pattern: "^(\s)+", replace: "");
  concluded += "  " + chomp(concl);
}

if (found) {

  version = "unknown";
  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  location = "/";

  # Version</span> 10.0.5
  # Version</span> 2022.04
  # Version</span> 2023.11.4
  vers = eregmatch(string: res, pattern: "Version</span> ([0-9.]+)", icase: TRUE);
  if (!isnull(vers[1])) {
    version = vers[1];
    concluded += '\n  ' + vers[0];
  }

  # If the system is in "Maintenance mode" the version is exposed differently like e.g.:
  #
  #      <div id="footer2">
  #        TeamCity 2023.05.4 (build 129421)
  #      </div>
  if (version == "unknown") {
    vers = eregmatch(string: res, pattern: "TeamCity ([0-9.]+) \(build [0-9]+\)", icase: TRUE);
    if (!isnull(vers[1])) {
      version = vers[1];
      concluded += '\n  ' + vers[0];
    }
  }

  set_kb_item(name: "jetbrains/teamcity/detected", value: TRUE);
  set_kb_item(name: "jetbrains/teamcity/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:jetbrains:teamcity:");
  if (!cpe)
    cpe = "cpe:/a:jetbrains:teamcity";

  register_product(cpe: cpe, location: location, port: port, service: "www");

  log_message(data: build_detection_report(app: "JetBrains TeamCity", version: version, install: location,
                                           cpe: cpe, concluded: concluded, concludedUrl: conclUrl),
              port: port);

  exit(0);
}

exit(0);
