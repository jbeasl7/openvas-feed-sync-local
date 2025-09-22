# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170794");
  script_version("2024-07-26T05:05:35+0000");
  script_tag(name:"last_modification", value:"2024-07-26 05:05:35 +0000 (Fri, 26 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-07-24 12:07:49 +0000 (Wed, 24 Jul 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:C");

  script_cve_id("CVE-2023-50734", "CVE-2023-50735", "CVE-2023-50736");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("RICOH Printers Multiple Vulnerabilities in PostScript Interpreter (ricoh-2024-000001)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_ricoh_printer_consolidation.nasl");
  script_mandatory_keys("ricoh/printer/detected");

  script_tag(name:"summary", value:"Multiple RICOH printers and multifunction printers are prone to
  multiple vulnerabilities in the PostScript interpreter.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2023-50734: Buffer overflow vulnerability in PostScript interpreter

  - CVE-2023-50735: Heap corruption vulnerability in PostScript interpreter

  - CVE-2023-50736: Memory corruption vulnerability in PostScript interpreter");

  script_tag(name:"affected", value:"P C200W and M C240FW devices with firmware versions prior to
  1.10.");

  script_tag(name:"solution", value:"Update to version 1.10 or later.");

  script_xref(name:"URL", value:"https://www.ricoh.com/products/security/vulnerabilities/vul?id=ricoh-2024-000001");
  script_xref(name:"URL", value:"https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000067-2024-000001");
  script_xref(name:"URL", value:"https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000065-2024-000001");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:ricoh:p_c200w_firmware",
                     "cpe:/o:ricoh:m_c240fw_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

version = infos["version"];
cpe = infos["cpe"];

if (version_is_less(version: version, test_version: "1.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.10");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
