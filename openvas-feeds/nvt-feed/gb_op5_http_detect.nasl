# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103379");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-01-09 10:33:57 +0100 (Mon, 09 Jan 2012)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ITRS OP5 Monitor Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of ITRS OP5 Monitor
  (formerly op5 Monitor).");

  script_xref(name:"URL", value:"https://www.itrsgroup.com/products/network-monitoring-op5-monitor");
  script_xref(name:"URL", value:"https://www.op5.com/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port(default: 443);

url = "/";
buf = http_get_cache(item: url, port: port);

# For the "/" main page:
# <title>Welcome to op5 portal</title>
# <p><br /><img src="portal/images/header_welcome.gif" alt="Welcome to op5 Portal" /></p>
# alt="op5 Monitor: Log in" title="op5 Monitor: Log in" /></a></dt>
# <title>ITRS OP5 Monitor Portal</title>
# <h1>Welcome to the ITRS OP5 Monitor Portal</h1>
# alt="op5 Monitor: Log in" title="OP5 Monitor: Log in" />
#
# For the "/monitor/index.php/auth/login":
# <title>ITRS OP5 Monitor</title>
# <h1>Log in to ITRS OP5 Monitor</h1>
#
# Some systems doesn't have the portal configured / installed and the request to the main page is redirecting with a 302 to something like e.g.:
#
# Location: https://<redacted>/monitor/
# Location: https://<redacted>/monitor/index.php
#
# when following these redirects we're getting again redirected to different locations like e.g.:
#
# Location: https://<redacted>/monitor/index.php/tac/index
# Location: https://<redacted>/monitor/index.php/auth/login
#
# In all cases the query to "/monitor/index.php/auth/login" worked so this is used here...
if (buf =~ "^HTTP/1\.[01] 30[0-9]" && egrep(string: buf, pattern: "^[Ll]ocation\s*:.*/monitor", icase: FALSE)) {
  redir_url = "/monitor/index.php/auth/login";
  buf = http_get_cache(item: redir_url, port: port);
}

if (concl = egrep(pattern: "(Welcome to op5 portal|op5 Monitor: Log in|ITRS OP5 Monitor Portal|>(ITRS OP5 Monitor|Log in to ITRS OP5 Monitor)<)", string: buf, icase: TRUE)) {

  concl = chomp(concl);
  install = url;
  # nb: For this case we still want to have "/" as the install location so we're only overwriting it
  # afterwards...
  if (redir_url)
    url = redir_url;
  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  version = "unknown";

  # Version: 7.1.6  | <a href="/monitor" title="Log in">Log in</a>
  # Version: 7.5.0  | <a href="/monitor" title="Log in">Log in</a>
  # Version: unknown  | <a href="/monitor"
  # nb: The "unknown" one above has been seen on version 5.3.2 on which the version was exposed on
  # the "/about.php" page (see below).
  vers = eregmatch(string: buf, pattern: 'Version: *([0-9.]+) *\\| *<a +href=".*/monitor"', icase: FALSE);
  if (!isnull(vers[1])) {
    version = vers[1];
    concl += '\n' + vers[0];
  }

  # nb:
  # - Newer 8.x versions are not exposing the version on the main portal page. This is also not
  #   available if the main portal isn't available and just redirecting to the "/monitor" login
  #   page (seen on two 9.x systems but also on a 7.5.x one). In both cases we can extract it from
  #   here.
  # - On such redirected systems the "/about.php" is usually available but at least for two systems
  #   it wasn't (probably since 9.x) so it will be extracted later from a second point if this
  #   fails.
  # - Make sure to not change "buf2" below to "buf" at it would overwrite the info required for the
  #   last version extracting code.
  if (version == "unknown") {
    url = "/about.php";
    buf2 = http_get_cache(item: url, port: port);

    # <p>Current OP5 Monitor System version: <strong>8.4.3
    # <p>Current OP5 Monitor System version: <strong>2019.a.2-op5.1.20190130130201.el7
    # <p>Current op5 System version: <strong>5.3.2
    # nb: The 5.x version above had a "Version: unknown" on the portal page for unknown reasons. As
    # we never know how many similar systems are still running "out there" we're also extracting the
    # version from this page here.
    vers = eregmatch(string: buf2, pattern: "Current OP5( Monitor)? System version:\s*(<strong>)?([0-9a-z.]+)", icase: TRUE);
    if (!isnull(vers[3])) {
      version = vers[3];
      concl += '\n' + vers[0];
      conclUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
    }
  }

  if (version == "unknown") {
    # src="/monitor/modules/license/views/brands/itrs_op5_expanded.png?v=9.4"
    # <link href="/monitor/application/views/css/layout.css?v=9.5" type="text/css"
    vers = eregmatch(string: buf, pattern: "/(itrs_op5_expanded\.png|layout\.css)\?v=([0-9a-z.]{3,})", icase: TRUE);
    if (!isnull(vers[2])) {
      version = vers[2];
      concl += '\n' + vers[0];
    }
  }

  set_kb_item(name: "op5/detected", value: TRUE);
  set_kb_item(name: "op5/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9a-z.]+)", base: "cpe:/a:op5:monitor:");
  if (!cpe)
    cpe = "cpe:/a:op5:monitor";

  # Only Linux based systems (RHEL, CentOS, Rocky Linux) according to:
  # https://docs.itrsgroup.com/docs/all/op5-monitor/compat-matrix-8x/index.html
  # https://docs.itrsgroup.com/docs/all/op5-monitor/compat-matrix/index.html
  os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", desc: "ITRS OP5 Monitor Detection (HTTP)",
                         port: port, banner_type: "OP5 Monitor HTTP Portal Page", runs_key: "unixoide");

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app:"ITRS OP5 Monitor", version: version, install: install, cpe: cpe,
                                           concludedUrl: conclUrl, concluded: concl),
              port: port);
}

exit(0);
