# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106198");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-08-24 14:38:56 +0700 (Wed, 24 Aug 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("IBM WebSphere Portal Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of IBM WebSphere Portal.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www-03.ibm.com/software/products/en/websphere-portal-family");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default: 443);

url = "/wps/portal/Home/Welcome/";
req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

# Handle 30x returns: we want to follow them
if (res =~ "^HTTP/1\.[01] 30.") {
  loc = http_extract_location_from_redirect(port: port, data: res, current_dir: url);
  if (loc) {
    cookie = eregmatch(pattern: "Set-Cookie: (DigestTracker=[A-Za-z;]+)", string: res);
    if (!isnull(cookie[1]))
      req = http_get_req(port: port, url: loc, add_headers: make_array("Cookie", cookie[1]));
    else
      req = http_get(port: port, item: loc);
    res = http_keepalive_send_recv(port: port, data: req);
  }
}

if ("IBM WebSphere Portal" >< res) {
  version = "unknown";

  req = http_get(port: port, item: "/wps/contenthandler/wcmrest/ProductVersion/");
  res = http_keepalive_send_recv(port: port, data: req);

  # Handle 30x returns: we want to follow them
  if (res =~ "^HTTP/1.. 30.") {
    loc = eregmatch(pattern: "Location: (.*\/wcmrest\/ProductVersion\/)", string: res);
    if(!isnull(loc[1])) {
      url = loc[1];
      req = http_get(port: port, item: url);
      res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

      if ("<major>" >< res && "<fix-level>" >< res) {
        concl = res;
        major = eregmatch(pattern: "<major>([0-9]+)</major>", string: res);
        minor = eregmatch(pattern: "<minor>([0-9]+)</minor>", string: res);
        maint = eregmatch(pattern: "<maintenance>([0-9]+)</maintenance>", string: res);
        minmaint = eregmatch(pattern: "<minor-maintenance>([0-9]+)</minor-maintenance>", string: res);
        fixlevel = eregmatch(pattern: "<fix-level>([0-9]+)</fix-level>", string: res);
        if (!isnull(major[1]) && !isnull(minor[1]) && !isnull(maint[1]) && !isnull(minmaint[1]) &&
            !isnull(fixlevel[1]))
          version = major[1] + '.' + minor[1] + '.' + maint[1] + '.' + minmaint[1] + '.' + fixlevel[1];
      }
    }
  }

  set_kb_item(name: "ibm_websphere_portal/installed", value: TRUE);
  if (version != "unknown")
    set_kb_item(name: "ibm_websphere_portal/installed", value: version);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:ibm:websphere_portal:");
  if (!cpe)
      cpe = 'cpe:/a:ibm:websphere_portal';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "IBM WebSphere Portal", version: version, install: "/",
                                           cpe: cpe, concluded: concl),
              port: port);
  exit(0);
}

exit(0);
