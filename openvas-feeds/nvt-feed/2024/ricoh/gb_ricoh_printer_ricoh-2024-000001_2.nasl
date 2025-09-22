# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170795");
  script_version("2024-07-26T05:05:35+0000");
  script_tag(name:"last_modification", value:"2024-07-26 05:05:35 +0000 (Fri, 26 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-07-24 12:07:49 +0000 (Wed, 24 Jul 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:C");

  script_cve_id("CVE-2023-50737");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("RICOH Printers Input Validation Vulnerability (ricoh-2024-000001)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ricoh_printer_consolidation.nasl");
  script_mandatory_keys("ricoh/printer/detected");

  script_tag(name:"summary", value:"Multiple RICOH printers and multifunction printers are prone to
  an input validation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Input validation vulnerability in one of the SE menu routines
  can be leveraged by an attacker to execute arbitrary code.");

  script_tag(name:"affected", value:"P C200W and M C240FW devices with firmware versions prior to
  1.09.");

  script_tag(name:"solution", value:"Update to version 1.09 or later.");

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

if (version_is_less(version: version, test_version: "1.09")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.09");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
