# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141135");
  script_version("2025-06-25T05:41:02+0000");
  script_tag(name:"last_modification", value:"2025-06-25 05:41:02 +0000 (Wed, 25 Jun 2025)");
  script_tag(name:"creation_date", value:"2018-06-01 10:51:22 +0700 (Fri, 01 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Quest / Dell KACE Systems Management Appliance (SMA) Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("KACE-Appliance/banner");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"HTTP based detection of Quest / Dell KACE Systems Management
  Appliance (SMA).");

  script_xref(name:"URL", value:"https://www.quest.com/products/kace-systems-management-appliance/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/userui/welcome.php";

# nb: If SAML is activated we need to grab a cookie first
req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

cookie = http_get_cookie_from_header(buf: res, pattern: "(kboxid=[^; ]+)");
if (cookie) {
  headers = make_array("Cookie", cookie);

  req = http_get_req(port: port, url: url, add_headers: headers);
  res = http_keepalive_send_recv(port: port, data: req);
}

# nb: K2000 devices are Systems Deployment appliances
if (res =~ "KACE-Appliance\s*:\s*k2000")
  exit(0);

if ((res !~ 'alt="SMA Logo"' && ('alt="Dell KACE Management Center"' >!< res || res !~ "K[0-9]000 Service Center")) &&
    (res !~ "X-(Dell)?KACE-Appliance" && "X-KBOX-Version" >!< res)) {
  url = "/login";
  res = http_get_cache(port: port, item: url);
  if (res !~ "X-(Dell)?KACE-Appliance" || 'class="k-page-message-box-container">' >!< res ||
      "Systems Deployment Appliance" >< res)
    exit(0);
}

model = "unknown";
version = "unknown";
location = "/";
hw_name = "Quest / Dell KACE Systems Management Appliance (SMA)";
os_name = hw_name + " Firmware";

# X-KACE-Appliance: K1000
# X-DellKACE-Appliance: k1000
mod = eregmatch(pattern: "X-(Dell)?KACE-Appliance\s*:\s*(K[0-9]+)", string: res, icase: TRUE);
if (!isnull(mod[2])) {
  model = toupper(mod[2]);
  hw_name += " " + model;
}

# /common/js/minified/kaccordion.js?build=12.0.149
vers = eregmatch(pattern: "\.(js|css)\?build=([0-9.]+)", string: res);
if (isnull(vers[2]))
  # X-DellKACE-Version: 6.4.120756
  # X-KACE-Version: 8.1.108
  vers = eregmatch(pattern: "X-(Dell)?KACE-Version\s*:\s*([0-9.]+)", string: res, icase: TRUE);

if (!isnull(vers[2]))
  version = vers[2];

concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

set_kb_item(name: "quest/kace/sma/detected", value: TRUE);
set_kb_item(name: "quest/kace/sma/http/detected", value: TRUE);

os_cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/o:quest:kace_systems_management_appliance_firmware:");
if (!os_cpe)
  os_cpe = "cpe:/o:quest:kace_systems_management_appliance_firmware";

if (model != "unknown")
  hw_cpe = "cpe:/h:quest:" + tolower(model);
else
  hw_cpe = "cpe:/h:quest:kace_systems_management_appliance";

os_register_and_report(os: os_name, cpe: os_cpe, runs_key: "unixoide",
                       desc: "Quest / Dell KACE Systems Management Appliance (SMA) Detection (HTTP)");

register_product(cpe: os_cpe, location: location, port: port, service: "www");
register_product(cpe: hw_cpe, location: location, port: port, service: "www");

report  = build_detection_report(app: os_name, version: version, install: location, cpe: os_cpe,
                                 concluded: vers[0], concludedUrl: concUrl);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe,
                                 concluded: mod[0]);

log_message(port: port, data: report);

exit(0);
