# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dahua:nvr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153716");
  script_version("2025-01-22T05:38:11+0000");
  script_tag(name:"last_modification", value:"2025-01-22 05:38:11 +0000 (Wed, 22 Jan 2025)");
  script_tag(name:"creation_date", value:"2025-01-06 07:30:28 +0000 (Mon, 06 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-19 16:06:28 +0000 (Thu, 19 Sep 2019)");

  script_cve_id("CVE-2019-9680");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Dahua Devices Information Disclosure Vulnerability (Jan 2025) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dahua_devices_http_detect.nasl");
  script_mandatory_keys("dahua/device/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Multiple Dahua devices (and their OEMs) are prone to an
  information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"This affects an unknown part of the file
  /web_caps/webCapsConfig of the component Web Interface. The manipulation leads to information
  disclosure.

  Note: This was initially tracked as CVE-2024-13131 but this CVE got rejected as a duplicate of
  CVE-2019-9680.");

  script_tag(name:"solution", value:"No known solution is available as of 06th January, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://netsecfish.notion.site/IntelBras-IP-Camera-Information-Disclosure-15e6b683e67c80a89f89daf59daa9ea8");

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
                    extra_check: '"vendor"')) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
