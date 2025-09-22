# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810964");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-06-28 16:34:52 +0530 (Wed, 28 Jun 2017)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Apache TomEE Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Apache TomEE.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://tomee.apache.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8080);

res = http_get_cache(item: "/", port: port);

if (res =~ "Server\s*:\s*Apache TomEE" || res =~ "<(title|h[13])>Apache Tomcat \(TomEE\)[^<]*</(title|h[13])>") {

  version = "unknown";

  # <title>Apache Tomcat (TomEE)/8.5.3 (7.0.1)</title>
  # <h1>Apache Tomcat (TomEE)/8.5.3 (7.0.1)</h1>
  # nb: 8.5.3 seems to be the Tomcat version
  # <title>Apache Tomcat (TomEE)/7.0.53 (1.6.0.2)</title>
  # <title>Apache Tomcat (TomEE)/8.0.32 (7.0.0-M3) - Error report</title>
  # <title>Apache Tomcat (TomEE)/7.0.34 - Error report</title>
  # <title>Apache Tomcat (TomEE)/7.0.39</title>
  # <h1>Apache Tomcat (TomEE)/7.0.39</h1>
  # nb: Error pages have a <h3>:
  # <h3>Apache Tomcat (TomEE)/7.0.34</h3>
  ver = eregmatch(pattern: "<(title|h[13])>Apache Tomcat \(TomEE\)/[^ ]+ \(([ 0-9A-Za-z.-]+)\)[^<]*</(title|h[13])>", string: res);
  if (!isnull(ver[2])) {
    concluded = ver[0];
    # nb: sometimes versions comes with '-' and space
    version = ereg_replace(string: ver[2], pattern: "-| ", replace: ".");
  } else {
    concl = egrep(string: res, pattern: "^Server\s*:\s*Apache TomEE", icase: TRUE);
    if (concl)
      concluded = chomp(concl);

    if (!concl) {
      concl = eregmatch(string: res, pattern: "<(title|h[13])>Apache Tomcat \(TomEE\)[^<]*</(title|h[13])>", icase: TRUE);
      if (concl)
        concluded = concl[0];
    }
  }

  set_kb_item(name: "apache/tomee/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9A-Za-z.]+)", base: "cpe:/a:apache:tomee:");
  if (!cpe)
    cpe = "cpe:/a:apache:tomee";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Apache TomEE Server", version: version, install: "/", cpe: cpe,
                                           concluded: concluded),
              port: port);
}

exit(0);
