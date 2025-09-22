# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:hp:laserjet";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171308");
  script_version("2025-03-19T05:38:35+0000");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2025-03-18 19:57:55 +0000 (Tue, 18 Mar 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2025-2268");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP LaserJet MFP M232-M237 Printers DoS Vulnerability (HPSBPI04013)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_hp_printer_consolidation.nasl");
  script_mandatory_keys("hp/printer/detected");

  script_tag(name:"summary", value:"HP LaserJet MFP M232-M237 Printer Series printers are prone to
  a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The HP LaserJet MFP M232-M237 Printer Series may be vulnerable
  to a denial of service attack when a specially crafted request message is sent via Internet
  Printing Protocol (IPP).");

  script_tag(name:"affected", value:"HP LaserJet MFP M232-M237 Printer series and LaserJet MFP
  M232e-M237e Printer series prior to version 20250209.");

  script_tag(name:"solution", value:"Update to version 20250209 or later.");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/ish_12114154-12114176-16/hpsbpi04013");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];

# nb: Checking for multiple patterns here since we could not find the exact model for testing and
# it is not clear how exactly the CPE is formed
if (cpe !~ "^cpe:/o:hp:laserjet_mfp_m(232|237)")
  exit(0);

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "20250209")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20250209");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
