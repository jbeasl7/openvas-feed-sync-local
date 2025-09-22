# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.147116");
  script_version("2022-03-28T13:52:53+0000");
  script_tag(name:"last_modification", value:"2022-03-28 13:52:53 +0000 (Mon, 28 Mar 2022)");
  script_tag(name:"creation_date", value:"2021-11-08 06:33:54 +0000 (Mon, 08 Nov 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("GitLab Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of GitLab.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_add_preference(name:"Personal access token", value:"", type:"password", id:1);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default: 443);

url = "/users/sign_in";

res = http_get_cache(port: port, item: url);
# nb: 302 if the instance is not initialized with a password yet, 502 if there is an error
if (!res || res !~ "^HTTP/1\.[01] (200|302.+/users/password|502)")
  exit(0);

detection_patterns = make_list(
  'content="GitLab"',
  ">About GitLab<",
  "gon\.gitlab_url",
  "<title>Sign in [^ ]+ GitLab</title>", # nb: The dot is U+00B7
  "https://about\.gitlab\.com/",
  # e.g.
  # <title>GitLab is not responding (502)</title>
  # <title>GitLab is starting...</title>
  "^\s*<title>GitLab is (not responding [^<]+|starting\.\.\.)</title>",
  "^[Ss]et-[Cc]ookie\s*:\s*_gitlab_session=[^;]+");

found = 0;
concluded = ""; # nb: To make openvas-nasl-lint happy...

foreach pattern (detection_patterns) {

  match = NULL;

  if ("_gitlab_session" >< pattern || "<title>GitLab is " >< pattern) {
    concl = egrep(string: res, pattern: pattern, icase: FALSE);
    if (concl)
      match = chomp(concl);
  } else {
    # nb: Don't use egrep() for other strings because it can't handle the U+00B7 mentioned above.
    concl = eregmatch(string: res, pattern: pattern, icase: FALSE);
    if (concl[0])
      match = concl[0];
  }

  if (match) {

    # nb: If the instance is not initialized with a password yet only none of the other pattern
    # matches because we're getting redirected to users/password/edit?reset_password_token= but the
    # session cookie should be exact enough. Similar for the "not responding" and "is starting".
    if ("_gitlab_session" >< pattern || "<title>GitLab is " >< pattern)
      found += 2;
    else
      found++;

    if (concluded)
      concluded += '\n';
    concluded += "  " + match;
  }
}

if (found > 1) {
  version = "unknown";
  concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  install = "/";

  # content="GitLab Enterprise Edition"
  # content="GitLab Community Edition"
  ed = eregmatch(pattern: 'content="GitLab ([^ ]+ Edition)"', string: res);
  if (!isnull(ed[1])) {
    edition = ed[1];
    concluded += '\n  ' + ed[0];
    if (ed[1] >< "Enterprise") {
       set_kb_item(name: "gitlab/ee/detected", value: TRUE);
    }
  }

  url = "/api/v4/version";
  res = http_get_cache( item:url, port:port );
  if( res && res =~ "^HTTP/1\.[01] 401" ) {

    pat = script_get_preference( "Personal access token", id:1 );

    if( ! pat ) {
      extra = "GitLab and '/api/v4/version' API detected. Providing a 'Personal access token' (see referenced URL) to the preferences of the VT 'GitLab Detection (HTTP)' (OID: 1.3.6.1.4.1.25623.1.0.147116) might allow to gather the version from the API.";
    } else {
      add_headers = make_array( "PRIVATE-TOKEN", pat );
      req = http_get_req( port:port, url:url, add_headers:add_headers, accept_header:"*/*" );
      res = http_keepalive_send_recv( port:port, data:req );

      if( res !~ "^HTTP/1\.[01] 200" || '{"version":"' >!< res ) {
        if( ! res )
          res = "No response";
        extra = 'Personal access token provided but login to the API failed with the following response:\n\n' + res;
      }

      # {"version":"14.9.1-ee","revision":"999a4a9a0bc"}
      vers = eregmatch( string:res, pattern:'\\{"version":"([0-9.]+)[^}]+\\}' );
      if( vers[1] ) {
        version = vers[1];
        concluded += '\n  ' + vers[0];
        concUrl += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }
  }

  set_kb_item(name: "gitlab/detected", value: TRUE);
  set_kb_item(name: "gitlab/http/detected", value: TRUE);
  set_kb_item(name: "gitlab/http/port", value: port);
  set_kb_item(name: "gitlab/http/" + port + "/installs",
              value: port + "#---#GitLab " + edition + "#---#" + install + "#---#" +
              version + "#---#" + concluded + "#---#" + concUrl + "#---#" + extra);
}

exit(0);
