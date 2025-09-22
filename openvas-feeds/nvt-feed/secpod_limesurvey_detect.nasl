# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900352");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2009-05-26 15:05:11 +0200 (Tue, 26 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("LimeSurvey Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of LimeSurvey.

  The script sends a connection request to the server and attempts to detect LimeSurvey and its version.");

  script_xref(name:"URL", value:"https://www.limesurvey.org");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port(default: 80);
if (!http_can_host_php(port: port))
  exit(0);

foreach dir(make_list_unique("/limesurvey", "/phpsurveyor", "/survey", "/PHPSurveyor", http_cgi_dirs(port: port))) {

  rep_dir = dir;
  if (dir == "/")
    dir = "";

  res = http_get_cache(item: dir + "/index.php", port: port);
  if (!res)
    continue;

  if (res =~ 'meta name="generator" content="LimeSurvey https?://(www\\.)?limesurvey\\.org"' || "<a href='#' data-limesurvey-lang='" >< res) {
    version = "unknown";

    url = dir + "/docs/release_notes.txt";
    req = http_get(item: url, port: port);
    res = http_keepalive_send_recv(port: port, data: req);

    # Changes from 2.6.6LTS (build 171111) to 2.6.7LTS (build 171208) Feb 23, 2018
    # Changes from 2.50+ (build 160816) to 2.50+ (build 160817) Aug 17, 2016
    # Changes from 2.70.0 (build 170921) to 2.71.0 (build 170925) Sept 25, 2017
    # Changes from 3.0.0-beta.1 (build 170720) to 3.0.0-beta.2 (build 170810) Aug 10, 2017
    # Changes from 1.87RC1 (build 7886) to 1.87RC2 (build 7922) [18-11-2009] - Legend: + new feature, # update feature, - bug fix
    # Changes from 0.992 to 0.993
    vers = eregmatch(pattern: "Changes from [^)]+\)? to ([0-9.]+)(\+|-?[0-9a-zA-Z.]+)?", string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      if (!isnull(vers[2]))
        version += vers[2];
      concUrl = url;
    }

    set_kb_item(name: "limesurvey/http/detected", value: TRUE);

    cpe = "cpe:/a:limesurvey:limesurvey";
    if (version != "unknown") {
      if (!isnull(vers[2])) {
        update_version = ereg_replace(string: vers[2], pattern: "[-.]", replace: "");
        cpe += ":" + vers[1] + ":" + update_version;
      } else {
        cpe += ":" + vers[1];
      }
    }

    register_product(cpe: cpe, location: rep_dir, port: port, service: "www");

    log_message(data: build_detection_report(app: "LimeSurvey", version: version, install: rep_dir, cpe: cpe,
                                             concluded: vers[0], concludedUrl: concUrl),
                port: port);
  }
  # PHPSurveyor or Surveyor are the product name of old LimeSurvey
  else if ("You have not provided a survey identification number" >< res) {
    version = "unknown";

    url = dir + "/docs/release_notes_and_upgrade_instructions.txt";
    req = http_get(item: url, port: port);
    res = http_keepalive_send_recv(port: port, data: req);

    vers = eregmatch(pattern: "Changes from ([0-9.]+)(\+|-?[0-9a-zA-Z.]+)? to ([0-9.]+)(\+|-?[0-9a-zA-Z.]+)?", string: res);
    if (!isnull(vers[3])) {
      version = vers[3];
      if (!isnull(vers[4]))
        version += vers[4];
      concUrl = url;
    }

    set_kb_item(name: "limesurvey/http/detected", value: TRUE);

    cpe = "cpe:/a:limesurvey:limesurvey";
    if (version != "unknown") {
      if (!isnull(vers[4])) {
        update_version = ereg_replace(string: vers[4], pattern: "[-.]", replace: "");
        cpe += ":" + vers[3] + ":" + update_version;
      } else {
        cpe += ":" + vers[3];
      }
    }

    register_product(cpe: cpe, location: rep_dir, port: port, service: "www");

    log_message(data: build_detection_report(app: "LimeSurvey", version: version, install: rep_dir, cpe: cpe,
                                             concluded: vers[0], concludedUrl: concUrl),
                port: port);
  }
}

exit(0);
