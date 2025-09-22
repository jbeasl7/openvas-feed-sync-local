# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:hp:";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171656");
  script_version("2025-08-01T15:45:48+0000");
  script_tag(name:"last_modification", value:"2025-08-01 15:45:48 +0000 (Fri, 01 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-01 11:09:54 +0000 (Fri, 01 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2025-43018");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Color LaserJet MFP M478-M479 / LaserJet Pro MFP M428-M429 Printers Information Disclosure Vulnerability (HPSBPI04040)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_hp_printer_consolidation.nasl");
  script_mandatory_keys("hp/printer/detected");

  script_tag(name:"summary", value:"Multiple HP LaserJet Pro printers are prone to an information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Certain HP LaserJet Pro printers may be vulnerable to
  information disclosure when a non-authenticated user queries a device's local address book.");

  script_tag(name:"affected", value:"HP Color LaserJet MFP M478-M479 series, HP LaserJet Pro MFP
  M428-M429 f series and HP LaserJet Pro MFP M428-M429 series prior to version 002.2508A.");

  script_tag(name:"solution", value:"Update to version 002.2508A or later.");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/ish_12807011-12807034-16/hpsbpi04040");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];

if (cpe !~ "^cpe:/o:hp:color_laserjet_(pro_)?mfp_m47[89]" &&
    cpe !~ "^cpe:/o:hp:laserjet_pro_mfp_m42[89]")
  exit(0);

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

# nb: We need to extract the version component to be compared with the one from the advisory
# M428fdw has firmware version like TETONXXXXN002.2512A.00
# M479fdw has firmware version like CLRWTRXXXN002.2445A.00
check_vers = eregmatch(pattern: "[A-Z]+([0-9]+\.[0-9A-Z]+)", string: version, icase: TRUE);
if (!check_vers[1])
  exit(0);

if (version_is_less(version: check_vers[1], test_version: "002.2508A")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "002.2508A");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
