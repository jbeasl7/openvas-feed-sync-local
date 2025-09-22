# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810306");
  script_version("2022-04-05T07:42:36+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-04-05 07:42:36 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"creation_date", value:"2016-12-09 12:11:43 +0530 (Fri, 09 Dec 2016)");
  script_name("Red Hat JBoss Enterprise Application Platform (EAP) Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://developers.redhat.com/products/eap/overview");

  script_tag(name:"summary", value:"HTTP based detection of the Red Hat JBoss Enterprise Application
  Platform (EAP).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");

port = http_get_port(default:443);
banner = http_get_remote_headers(port:port);

url1 = "/";
res1 = http_get_cache(item:url1, port:port);

url2 = "/noredirect.html";
res2 = http_get_cache(item:url2, port:port);

detection_patterns = make_list(
  "^\s*<h3>Your Red Hat JBoss Enterprise Application Platform is running\.</h3>",
  # Server: JBoss-EAP/7
  "^[Ss]erver\s*:\s*JBoss-EAP",
  # On "/":
  # <title>JBoss EAP 7</title>
  # <title>Welcome to JBoss EAP 7</title>
  "^\s*<title>(Welcome to )?JBoss EAP[^<]*</title>",
  # on "/noredirect":
  # <title>JBoss EAP 7 - Console Redirect Unavailable</title>
  "^\s*<title>(Welcome to )?JBoss EAP[^<]*- Console Redirect Unavailable</title>",
  # <title>EAP 6</title>
  "^\s*<title>EAP [0-9.]+</title>",
  # <h1>Welcome to JBoss EAP 7</h1>
  # <h1>Welcome to JBoss EAP 6</h1>
  "^\s*<h1>Welcome to JBoss EAP[^<]*</h1>",
  # on "/noredirect":
  # <p>To access the Administration console you should contact the administrator responsible for this
  #    JBoss EAP installation and ask them to provide you with the correct address.</p>
  "JBoss EAP installation and ask them to provide you with the correct address\.");

found = 0;
concluded = ""; # nb: To make openvas-nasl-lint happy...
conclUrl = ""; # nb: To make openvas-nasl-lint happy...

foreach pattern(detection_patterns) {

  if("^[Ss]erver" >< pattern) {
    concl = egrep(string:banner, pattern:pattern, icase:FALSE);
    _conclUrl = "  " + http_report_vuln_url(port:port, url:url1, url_only:TRUE);
  } else if("JBoss EAP installation" >< pattern || "Console Redirect Unavailable" >< pattern) {
    _conclUrl = "  " + http_report_vuln_url(port:port, url:url2, url_only:TRUE);
    concl = egrep(string:res2, pattern:pattern, icase:FALSE);
  } else {
    concl = egrep(string:res1, pattern:pattern, icase:FALSE);
    _conclUrl = "  " + http_report_vuln_url(port:port, url:url1, url_only:TRUE);
  }

  if(concl) {
    if(concluded)
      concluded += '\n';

    # nb: Minor formatting change for the reporting.
    concl = chomp(concl);
    concl = ereg_replace(string:concl, pattern:"^(\s+)", replace:"");
    concluded += "  " + concl;

    if(!egrep(string:conclUrl, pattern:_conclUrl + "$", icase:FALSE)) {
      if(conclUrl)
        conclUrl += '\n';

      conclUrl += _conclUrl;
    }

    found++;
  }
}

if(found > 0) {

  install = "/";
  version = "unknown";

  vers = eregmatch(pattern:"Server\s*:\s*JBoss-EAP/([0-9.]+)", string:concluded, icase:FALSE);
  if(vers[1])
    version = vers[1];

  if(version == "unknown") {

    vers = eregmatch(pattern:"<title>(Welcome to )?JBoss EAP ([0-9.]+)[^<]*</title>", string:concluded, icase:FALSE);
    if(vers[2])
      version = vers[2];
  }

  if(version == "unknown") {

    vers = eregmatch(pattern:"<h1>Welcome to JBoss EAP ([0-9.]+)[^<]*</h1>", string:concluded, icase:FALSE);
    if(vers[1])
      version = vers[1];
  }

  if(version == "unknown") {

    vers = eregmatch(pattern:"<title>EAP ([0-9.]+)[^<]*</title>", string:concluded, icase:FALSE);
    if(vers[1])
      version = vers[1];
  }

  # nb: Some additional "fingerprinting" from an error page which was previously done in
  # gb_red_hat_jboss_http_detect.nasl for EAP but got moved here.
  url = "/vt-test-non-existent.html";
  res = http_get_cache(item:url, port:port, fetch404:TRUE);
  if(res && res =~ "^HTTP/1\.[01] 404") {

    # nb: Pattern have been taken from EAP installations in the past. We might want to extend
    # and/or verify these again in the future.
    errorPatterns = make_array("JBoss Web/7\.2\.0\.Final-redhat-1", "6.1",
                               "JBoss Web/7\.2\.2\.Final-redhat-1", "6.2",
                               "JBoss Web/7\.4\.8\.Final-redhat-4", "6.3",
                               "JBoss Web/7\.5\.7\.Final-redhat-1", "6.4");

    res = http_extract_body_from_response(data:res);
    foreach errorPattern(keys(errorPatterns)) {
      if(found = eregmatch(string:res, pattern:errorPattern, icase:FALSE)) {
        concluded += '\n  ' + found[0];
        conclUrl  += '\n  ' + http_report_vuln_url(port:port, url:url, url_only:TRUE);

        tmpVers = errorPatterns[errorPattern];

        if(version == "unknown" || version_is_greater(version:tmpVers, test_version:version))
          version = tmpVers;

        break;
      }
    }
  }

  set_kb_item(name:"redhat/jboss/eap/detected", value:TRUE);
  set_kb_item(name:"redhat/jboss/eap/http/detected", value:TRUE);
  set_kb_item(name:"redhat/jboss/prds/detected", value:TRUE);
  set_kb_item(name:"redhat/jboss/prds/http/detected", value:TRUE);

  cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:redhat:jboss_enterprise_application_platform:");
  if(!cpe)
    cpe = "cpe:/a:redhat:jboss_enterprise_application_platform";

  register_product(cpe:cpe, location:install, port:port, service:"www");

  log_message(data:build_detection_report(app:"Red Hat Enterprise Application Platform (EAP)",
                                          version:version,
                                          install:install,
                                          cpe:cpe,
                                          concludedUrl:conclUrl,
                                          concluded:concluded),
              port:port);
}

exit(0);
