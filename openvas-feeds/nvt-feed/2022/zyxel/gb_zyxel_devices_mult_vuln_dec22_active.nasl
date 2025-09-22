# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

CPE_PREFIX = "cpe:/o:zyxel:";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149030");
  script_version("2025-06-25T05:41:02+0000");
  script_tag(name:"last_modification", value:"2025-06-25 05:41:02 +0000 (Wed, 25 Jun 2025)");
  script_tag(name:"creation_date", value:"2022-12-19 06:33:38 +0000 (Mon, 19 Dec 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-08 18:15:00 +0000 (Mon, 08 May 2023)");

  script_cve_id("CVE-2022-45440", "CVE-2023-28769", "CVE-2023-28770");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zyxel Devices Multiple Vulnerabilities (Dec 2022) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_zyxel_router_consolidation.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_zyxel_vpn_firewall_consolidation.nasl");
  script_mandatory_keys("zyxel/device/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Multiple Zyxel devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-28769: Multiple unauthenticated buffer overflows in zhttpd and libclinkc.so

  - CVE-2023-28770: Unauthenticated local file disclosure (LFI) in zhttpd

  - No CVE: Unsafe storage of sensitive data

  - No CVE: Authenticated command injection

  - No CVE: Broken access control

  - CVE-2022-45440: Processing of symbolic links in ftpd

  - No CVE: Inadequate CSRF implementation

  - No CVE: Stored cross-site scripting (XSS)");

  script_tag(name:"affected", value:"Multiple Zyxel devices are affected.");

  script_tag(name:"solution", value:"See the referenced advisories.

  Note: Some devices are End of Live (EoL) and will not receive any fix.");

  script_xref(name:"URL", value:"https://sec-consult.com/vulnerability-lab/advisory/multiple-critical-vulnerabilities-in-multiple-zyxel-devices/");
  script_xref(name:"URL", value:"https://sec-consult.com/blog/detail/enemy-within-unauthenticated-buffer-overflows-zyxel-routers/");
  script_xref(name:"URL", value:"https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-multiple-vulnerabilities");
  script_xref(name:"URL", value:"https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-multiple-vulnerabilities-affected-model-list");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("traversal_func.inc");
include("os_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www"))
  exit(0);

cpe = infos["cpe"];
port = infos["port"];

if (!dir = get_app_location(cpe: cpe, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files("linux");

foreach pattern (keys(files)) {
  url = dir + "/Export_Log?/" + files[pattern];

  if (http_vuln_check(port: port, url: url, pattern: pattern)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
