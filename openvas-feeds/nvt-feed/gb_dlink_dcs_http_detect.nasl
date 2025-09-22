# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144537");
  script_version("2025-07-01T05:42:02+0000");
  script_tag(name:"last_modification", value:"2025-07-01 05:42:02 +0000 (Tue, 01 Jul 2025)");
  script_tag(name:"creation_date", value:"2020-09-09 05:30:36 +0000 (Wed, 09 Sep 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("D-Link DCS IP Camera Devices Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("d-link/dcs/banner");

  script_tag(name:"summary", value:"HTTP based detection of D-Link DCS IP camera devices.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

if (!banner = http_get_remote_headers(port: port))
  exit(0);

# Important: If changing / extending the response / banner check pattern below please make sure to
# handle the relevant check / handling in gb_get_http_banner.nasl accordingly.
if (!concl = egrep(string: banner, pattern: '(Server\\s*:\\s*dcs-lig-httpd|(Basic|Digest) realm="DCS-[0-9]+)', icase: FALSE))
  exit(0);

concluded = chomp(concl);

install = "/";
version = "unknown";
hw_version = "unknown";
model = "unknown";

fw_conclurl = http_report_vuln_url(port: port, url: install, url_only: TRUE);

url = "/common/info.cgi";
res = http_get_cache(item: url, port: port);
if (res =~ "HTTP/(2|1.[01]) 200" && res =~ "model=DCS-([0-9A-Z]+)") {

  fw_conclurl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
  # model=DCS-936L
  mod = eregmatch(pattern: "model=DCS-([0-9A-Z]+)", string: res);
  if (!isnull(mod[1])) {
    model = mod[1];
    concluded += '\n    ' + mod[0];
  }
  # version=1.07
  fw_vers = eregmatch(pattern: "version=([.0-9]+)", string: res);
  if (!isnull(fw_vers[1])) {
    version = fw_vers[1];
    concluded += '\n    ' + fw_vers[0];
  }
  # hw_version=A
  hw_vers = eregmatch(pattern: "hw_version=([A-Z0-9]+)", string: res);
  if (!isnull(hw_vers[1])) {
    hw_version = hw_vers[1];
    hw_concluded = hw_vers[0];
    hw_conclurl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }
} else  if (banner =~ '(Basic|Digest) realm="DCS') {
  # WWW-Authenticate: Basic realm="DCS-2530L"
  # WWW-Authenticate: Basic realm="DCS-932L_68"
  # WWW-Authenticate: Basic realm="DCS-930L_AE"
  # WWW-Authenticate: Digest realm="DCS-2530L"
  # WWW-Authenticate: Basic realm="DCS-2103"
  # WWW-Authenticate: Digest realm="DCS-2530L", qop="auth", nonce="<redacted>", opaque="<redacted>", algorithm="MD5", stale="FALSE"
  # WWW-Authenticate: Digest realm="DCS-930LB1_D1",qop="auth", nonce="<redacted>"
  #
  mod = eregmatch(pattern: '(Basic|Digest) realm="DCS\\-([^"]+)"', string: banner);
  if (!isnull(mod[2])) {
    model = mod[2];

    # nb: For 932L and DCS-930L devices the parts after "_" seems to be random and have been dropped
    # for now.
    model = ereg_replace(string: model, pattern: "(_[0-9A-Z]+)", replace: "");
  }
}

set_kb_item(name: "d-link/http/detected", value: TRUE);

set_kb_item(name: "d-link/dcs/detected", value: TRUE);
set_kb_item(name: "d-link/dcs/http/detected", value: TRUE);
set_kb_item(name: "d-link/dcs/http/port", value: port);
set_kb_item(name: "d-link/dcs/http/" + port + "/model", value: model);
set_kb_item(name: "d-link/dcs/http/" + port + "/fw_version", value: version);
set_kb_item(name: "d-link/dcs/http/" + port + "/hw_version", value: hw_version);
set_kb_item(name: "d-link/dcs/http/" + port + "/fw_concluded", value: concluded);
set_kb_item(name: "d-link/dcs/http/" + port + "/fw_conclurl", value: fw_conclurl);

if (hw_concluded)
  set_kb_item(name: "d-link/dcs/http/" + port + "/hw_concluded", value: hw_concluded);
if (hw_conclurl)
  set_kb_item(name: "d-link/dcs/http/" + port + "/hw_conclurl", value: hw_conclurl);

exit(0);
