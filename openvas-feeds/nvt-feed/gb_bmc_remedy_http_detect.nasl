# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106504");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2017-01-09 10:12:05 +0700 (Mon, 09 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("BMC Remedy Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of BMC Remedy.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.bmc.com/it-solutions/remedy-itsm.html");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/arsys/shared/login.jsp";
res = http_get_cache(port: port, item: url);

# <title>BMC&nbsp;Remedy&nbsp;Mid&nbsp;Tier&nbsp;9.1 - Login</title>
#
# which might be also just something like e.g.:
#
# <title>MidTier - Login</title>
#
# <form class="loginForm" name="loginForm" METHOD="post" ACTION="/arsys/servlet/LoginServlet"
#
# sometimes also over multiple lines:
#
# <form name="loginForm" METHOD="post"
#  ACTION="/arsys/servlet/LoginServlet"
#  enctype="x-www-form-encoded">
#
# <a href="http://www.bmc.com">BMC Software, Inc.</a> All rights reserved.</li>
#
#     Copyright (c) 2001-2013 BMC Software, Inc.
#
if (('"product">BMC Remedy Action Request System' >< res || "title>BMC&nbsp;Remedy&nbsp;Mid&nbsp;Tier" >< res) ||
    ('ACTION="/arsys/servlet/LoginServlet"' >< res && "BMC Software, Inc." >< res)
   ) {

  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  version = "unknown";
  install = "/";

  # e.g.
  # /arsys/resources/javascript/8.1.SP02
  # /arsys/resources/javascript/8.1.01
  # /arsys/resources/javascript/8.1.00
  # /arsys/resources/javascript/7.6.04
  # /arsys/resources/javascript/9.1.07
  # /arsys/resources/javascript/9.1.10
  # /arsys/resources/javascript/9.1.10.002
  # /arsys/resources/javascript/9.1.10.004
  # /arsys/resources/javascript/22.1.04
  vers = eregmatch(pattern: "/arsys/resources/javascript/([0-9.SP]+)", string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "bmc/remedy/detected", value: TRUE);
  set_kb_item(name: "bmc/remedy/http/detected", value: TRUE);

  cpe = build_cpe(value: tolower(version), exp: "^([0-9.sp]+)", base: "cpe:/a:bmc:remedy_action_request_system:");
  if (!cpe)
    cpe = "cpe:/a:bmc:remedy_action_request_system";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "BMC Remedy", version: version, install: install, cpe: cpe,
                                           concludedUrl: conclUrl, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
