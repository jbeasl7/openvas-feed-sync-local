# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:hp:laserjet";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154074");
  script_version("2025-02-25T13:24:30+0000");
  script_tag(name:"last_modification", value:"2025-02-25 13:24:30 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"creation_date", value:"2025-02-25 02:59:55 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2025-26506", "CVE-2025-26508");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP LaserJet Pro Printers Multiple Vulnerabilities (HPSBPI04007)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_hp_printer_consolidation.nasl");
  script_mandatory_keys("hp/printer/detected");

  script_tag(name:"summary", value:"Multiple HP LaserJet Pro printers are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Certain HP LaserJet Pro Printers may potentially be vulnerable
  to remote code execution (RCE) and elevation of privilege when processing a PostScript print
  job.");

  script_tag(name:"affected", value:"Certain HP LaserJet Pro Printers (see the referenced vendor
  advisory for a complete list) prior to version 6.17.5.34-202412122146.");

  script_tag(name:"solution", value:"Update to version 6.17.5.34-202412122146 or later.");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/ish_11953771-11953793-16/hpsbpi04007");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];

if (cpe !~ "^cpe:/o:hp:laserjet_pro_420[1-3]" &&
    cpe !~ "^cpe:/o:hp:laserjet_mfp_430[1-3]" &&
    cpe !~ "^cpe:/o:hp:laserjet_mfp_(330[1-4]|3388)" &&
    cpe !~ "^cpe:/o:hp:laserjet_pro_(320[1-4]|3288)")
  exit(0);

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "6.17.5.34.202412122146")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.17.5.34-202412122146");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
