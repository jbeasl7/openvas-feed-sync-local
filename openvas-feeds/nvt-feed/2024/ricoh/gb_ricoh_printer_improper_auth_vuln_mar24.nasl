# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170790");
  script_version("2024-06-17T08:31:37+0000");
  script_tag(name:"last_modification", value:"2024-06-17 08:31:37 +0000 (Mon, 17 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-06-14 07:33:20 +0000 (Fri, 14 Jun 2024)");
  script_tag(name:"cvss_base", value:"2.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2024-21824");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("RICOH Printers Improper Authentication Vulnerability (Mar 2024)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ricoh_printer_consolidation.nasl");
  script_mandatory_keys("ricoh/printer/detected");

  script_tag(name:"summary", value:"Multiple RICOH printers and multifunction printers are prone to
  an improper authentication vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"A vulnerability in Web Based Management could allow an
  unauthenticated, remote attacker to log into the server settings screen by using cookie values
  taken through eavesdropped communications or by attacks to the user's web browser.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for updated firmware versions.");

  script_xref(name:"URL", value:"https://jvn.jp/en/jp/JVN82749078/");
  script_xref(name:"URL", value:"https://www.ricoh.com/products/security/vulnerabilities/vul?id=ricoh-2024-000002");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:ricoh:sp_230dnw_firmware",
                     "cpe:/o:ricoh:p_201w_firmware",
                     "cpe:/o:ricoh:m_340w_firmware",
                     "cpe:/o:ricoh:sp_230sfnw_firmware",
                     "cpe:/o:ricoh:m_340fw_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

version = infos["version"];
cpe = infos["cpe"];

if (cpe == "cpe:/o:ricoh:sp_230dnw_firmware") {
  if (version_is_less_equal(version: version, test_version: "1.05")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:ricoh:p_201w_firmware") {
  if (version_is_less_equal(version: version, test_version: "1.02")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:ricoh:m_340w_firmware") {
  if (version_is_less_equal(version: version, test_version: "F")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:ricoh:sp_230sfnw_firmware") {
  if (version_is_less_equal(version: version, test_version: "E")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:ricoh:m_340fw_firmware") {
  if (version_is_less_equal(version: version, test_version: "G")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
