# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:hp:laserjet";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171151");
  script_version("2025-02-10T05:38:01+0000");
  script_tag(name:"last_modification", value:"2025-02-10 05:38:01 +0000 (Mon, 10 Feb 2025)");
  script_tag(name:"creation_date", value:"2025-02-07 11:29:59 +0000 (Fri, 07 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2025-1004");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP LaserJet Pro Printers DoS Vulnerability (HPSBPI03998)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_hp_printer_consolidation.nasl");
  script_mandatory_keys("hp/printer/detected");

  script_tag(name:"summary", value:"Multiple HP LaserJet Pro printers are prone to a denial of
  service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Certain HP LaserJet Pro printers may potentially experience a
  denial of service when a user sends a raw JPEG file to the printer via IPP (Internet Printing
  Protocol).");

  script_tag(name:"affected", value:"HP Color  LaserJet Pro MFP M227 series, LaserJet Pro MFP M230
  series  LaserJet Pro MFP M148-M149 series prior to version 20241025.");

  script_tag(name:"solution", value:"Update to version 20241025 or later.");

  script_xref(name:"URL", value:"https://support.hp.com/au-en/document/ish_11927586-11927615-16/hpsbpi03998");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];

# nb: Checking for multiple cases here, because it was noticed during testing that
# M227 models are exposed as LaserJet MFP M227 and M148 as LaserJet Pro M148
if (cpe !~ "^cpe:/o:hp:laserjet_pro_m(148|149)" &&
    cpe !~ "^cpe:/o:hp:laserjet_mfp_m(227|230)" &&
    cpe !~ "^cpe:/o:hp:laserjet_pro_mfp_m(227|230)")
  exit(0);

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "20241025")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20241025");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
