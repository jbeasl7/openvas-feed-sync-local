# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openprinting:cups";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155319");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-09-15 02:54:21 +0000 (Mon, 15 Sep 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:C/A:C");

  script_cve_id("CVE-2025-58060", "CVE-2025-58364");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CUPS < 2.4.13 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_cups_http_detect.nasl");
  script_mandatory_keys("cups/detected");

  script_tag(name:"summary", value:"CUPS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-58060: Authentication bypass with AuthType Negotiate

  - CVE-2025-58364: Remote DoS via null dereference");

  script_tag(name:"affected", value:"CUPS prior to version 2.4.13.");

  script_tag(name:"solution", value:"Update to version 2.4.13 or later.");

  script_xref(name:"URL", value:"https://github.com/OpenPrinting/cups/security/advisories/GHSA-4c68-qgrh-rmmq");
  script_xref(name:"URL", value:"https://github.com/OpenPrinting/cups/security/advisories/GHSA-7qx3-r744-6qv4");
  script_xref(name:"URL", value:"https://github.com/OpenPrinting/cups/releases/tag/v2.4.13");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.4.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.13");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
