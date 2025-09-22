# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:hp:laserjet_pro_mfp_m12";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152736");
  script_version("2024-07-24T05:06:37+0000");
  script_tag(name:"last_modification", value:"2024-07-24 05:06:37 +0000 (Wed, 24 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-07-23 04:45:26 +0000 (Tue, 23 Jul 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2024-2301");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Printer XSS Vulnerability (HPSBPI03940)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_hp_printer_consolidation.nasl");
  script_mandatory_keys("hp/printer/detected");

  script_tag(name:"summary", value:"Multiple HP printers are prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Certain HP LaserJet Pro devices are potentially vulnerable to a
  cross-site scripting (XSS) attack via the web management interface of the device.");

  script_tag(name:"affected", value:"HP LaserJet Pro MFP M125 series, M126 series, M127 series and
  M128 series prior to version 20230330.");

  script_tag(name:"solution", value:"Update to version 20230330 or later.");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/ish_10617756-10617781-16/hpsbpi03940");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];

if (cpe !~ "^cpe:/o:hp:laserjet_pro_mfp_m12[5678]")
  exit(0);

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "20230330")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20230330");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
