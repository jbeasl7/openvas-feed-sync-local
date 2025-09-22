# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:amcrest:ip_camera";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153698");
  script_version("2025-01-03T06:28:02+0000");
  script_tag(name:"last_modification", value:"2025-01-03 06:28:02 +0000 (Fri, 03 Jan 2025)");
  script_tag(name:"creation_date", value:"2025-01-02 05:16:45 +0000 (Thu, 02 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2024-12984");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Amcrest Technologies IP Camera Information Disclosure Vulnerability (Dec 2024) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_amcrest_ip_camera_http_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("amcrest/ip_camera/http/detected");

  script_tag(name:"summary", value:"Multiple Amcrest Technologies IP Cameras are prone to an
  information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"This affects an unknown part of the file
  /web_caps/webCapsConfig of the component web interface. The manipulation leads to information
  disclosure.");

  script_tag(name:"affected", value:"Amcrest IP2M-841B, IP2M-841W, IPC-IP2M-841B, IPC-IP3M-943B,
  IPC-IP3M-943S, IPC-IP3M-HX2B and IPC-IPM-721S up to 20241211 are known to be affected. Other
  models or versions might be affected as well.");

  script_tag(name:"solution", value:"No known solution is available as of 02nd January, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://netsecfish.notion.site/AMCREST-IP-Camera-Information-Disclosure-1596b683e67c8045ad10c16b3eed456f");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/web_caps/webCapsConfig";

if (http_vuln_check(port: port, url: url, pattern: '"deviceType"', check_header: TRUE,
                    extra_check: '"WebVersion"')) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
