# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:mikrotik:routeros";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155025");
  script_version("2025-07-25T15:43:57+0000");
  script_tag(name:"last_modification", value:"2025-07-25 15:43:57 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-25 05:38:09 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"cvss_base", value:"4.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2025-6563");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MikroTik RouterOS 7.x < 7.19.2 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/routeros/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attacker can inject the 'javascript' protocol in the 'dst'
  parameter. When the victim browses to the malicious URL and logs in, the XSS executes. The POST
  request used to login, can also be converted to a GET request, allowing an attacker to send a
  specifically crafted URL that automatically logs in the victim (into the attacker's account) and
  triggers the payload.");

  script_tag(name:"affected", value:"MikroTik RouterOS version 7.x through 7.19.1.");

  script_tag(name:"solution", value:"Update to version 7.19.2 or later.");

  script_xref(name:"URL", value:"https://mikrotik.com/download/changelogs");
  script_xref(name:"URL", value:"https://www.toreon.com/how-a-ski-trip-led-to-a-cve-in-a-wi-fi-hotspot/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.19.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.19.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
