# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:lexmark:mx6500e";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154194");
  script_version("2025-03-14T15:40:32+0000");
  script_tag(name:"last_modification", value:"2025-03-14 15:40:32 +0000 (Fri, 14 Mar 2025)");
  script_tag(name:"creation_date", value:"2025-03-14 04:25:53 +0000 (Fri, 14 Mar 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2020-35546");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Lexmark Printer Race Condition Vulnerability (CVE-2020-35546)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_lexmark_printer_consolidation.nasl");
  script_mandatory_keys("lexmark_printer/detected");

  script_tag(name:"summary", value:"Lexmark MX6500 printer devices are prone to a race condition
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the
  target host.");

  script_tag(name:"insight", value:"A race condition exists while processing the state of the two
  security jumpers in an MX6500e. This can cause occasional misreads of the security jumper state
  during boot, causing the device to incorrectly believe the security jumper state has changed. The
  result is that security access controls may be unexpectedly reset.");

  script_tag(name:"solution", value:"Update to version LW75.JD.P297 or later.");

  script_xref(name:"URL", value:"https://publications.lexmark.com/publications/security-alerts/CVE-2020-35546.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if (!version = toupper(get_app_version(cpe: cpe, port: port, nofork: TRUE)))
  exit(0);

if (version_is_less(version: version, test_version: "LW75.JD.P297")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "LW75.JD.P297");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
