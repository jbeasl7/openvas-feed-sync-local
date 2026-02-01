# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.125675");
  script_version("2026-01-28T05:49:43+0000");
  script_tag(name:"last_modification", value:"2026-01-28 05:49:43 +0000 (Wed, 28 Jan 2026)");
  script_tag(name:"creation_date", value:"2026-01-26 15:16:20 +0000 (Mon, 26 Jan 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2025-14236");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Canon Printers Buffer Overflow Vulnerability (CP2026-001)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_canon_printer_consolidation.nasl");
  script_mandatory_keys("canon/printer/detected");

  script_tag(name:"summary", value:"A buffer overflow vulnerability have been identified for
  certain Canon Small Office Multifunction Printers and Laser Printers.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Buffer overflow in Address Book attribute tag processing.");

  script_tag(name:"affected", value:"Multiple Canon printers having firmware version 06.02 and
  prior.");

  script_tag(name:"solution", value:"Update to version 07.01 or later.");

  script_xref(name:"URL", value:"https://psirt.canon/advisory-information/cp2026-001/");
  script_xref(name:"URL", value:"https://canon.a.bigcontent.io/v1/static/cp2026-001_affected_models_20251230_30ed178db85d45238b2293d375781c00");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-14236");
  script_xref(name:"URL", value:"https://www.usa.canon.com/support/canon-product-advisories/Service-Notice-Regarding-Remediation-Measure-Against-Potential-Buffer-Overflow-Vulnerability-in-Laser-Printers-and-Small-Office-Multifunctional-Printers");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

# nb: Added MF models with and without i-SENSYS as i-SENSYS seems to be only a branding name
cpe_list = make_list("cpe:/o:canon:mf451dw_firmware",
                     "cpe:/o:canon:mf452dw_firmware",
                     "cpe:/o:canon:mf453dw_firmware",
                     "cpe:/o:canon:mf455dw_firmware",
                     "cpe:/o:canon:mf552dw_firmware",
                     "cpe:/o:canon:mf553dw_firmware",
                     "cpe:/o:canon:mf651cw_firmware",
                     "cpe:/o:canon:mf652cw_firmware",
                     "cpe:/o:canon:mf653cdw_firmware",
                     "cpe:/o:canon:mf654cdw_firmware",
                     "cpe:/o:canon:mf655cdw_firmware",
                     "cpe:/o:canon:mf656cdw_firmware",
                     "cpe:/o:canon:mf657cdw_firmware",
                     "cpe:/o:canon:imagerunner_1643i_ii_firmware",
                     "cpe:/o:canon:imagerunner_1643if_ii_firmware",
                     "cpe:/o:canon:i-sensys_mf451dw_firmware",
                     "cpe:/o:canon:i-sensys_mf452dw_firmware",
                     "cpe:/o:canon:i-sensys_mf453dw_firmware",
                     "cpe:/o:canon:i-sensys_mf455dw_firmware",
                     "cpe:/o:canon:i-sensys_mf552dw_firmware",
                     "cpe:/o:canon:i-sensys_mf553dw_firmware",
                     "cpe:/o:canon:i-sensys_mf651cw_firmware",
                     "cpe:/o:canon:i-sensys_mf652cw_firmware",
                     "cpe:/o:canon:i-sensys_mf653cdw_firmware",
                     "cpe:/o:canon:i-sensys_mf654cdw_firmware",
                     "cpe:/o:canon:i-sensys_mf655cdw_firmware",
                     "cpe:/o:canon:i-sensys_mf656cdw_firmware",
                     "cpe:/o:canon:i-sensys_mf657cdw_firmware",
                     "cpe:/o:canon:i-sensys_x_1238i_ii_firmware",
                     "cpe:/o:canon:i-sensys_x_1238if_ii_firmware");


if (!infos = get_app_port_from_list(cpe_list: cpe_list, first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "06.02")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "07.01");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
