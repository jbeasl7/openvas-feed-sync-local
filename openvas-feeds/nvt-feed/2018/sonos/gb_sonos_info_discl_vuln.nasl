# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/a:sonos:";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141020");
  script_version("2024-09-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-09-19 05:05:57 +0000 (Thu, 19 Sep 2024)");
  script_tag(name:"creation_date", value:"2018-04-24 10:15:48 +0700 (Tue, 24 Apr 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Sonos Speakers Information Disclosure Vulnerability (Apr 2018) - Active Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_sonos_upnp_tcp_detect.nasl");
  script_require_ports("Services/www", 1400);
  script_mandatory_keys("sonos/upnp/detected");

  script_tag(name:"summary", value:"Sonos speakers are prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"By accessing /status or /tools it is possible for an
  unauthenticated attacker to gather information about the device settings and possible other
  information. This may lead to further attacks.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"https://conference.hitb.org/hitbsecconf2018ams/materials/D1%20COMMSEC%20-%20Stephen%20Hilt%20-%20Hacking%20IoT%20Speakers.pdf");
  script_xref(name:"URL", value:"https://conference.hitb.org/hitbsecconf2018ams/sessions/commsec-the-sound-of-a-targeted-attack-attacking-iot-speakers/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www"))
  exit(0);

port = infos["port"];
CPE = infos["cpe"];

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/status/topology";
if (http_vuln_check(port: port, url: url, pattern: "<ZPSupportInfo><ZonePlayers>", check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
