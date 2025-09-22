# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.151712");
  script_version("2024-02-14T05:07:39+0000");
  script_tag(name:"last_modification", value:"2024-02-14 05:07:39 +0000 (Wed, 14 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-02-13 04:40:06 +0000 (Tue, 13 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 19:51:42 +0000 (Tue, 13 Feb 2024)");

  script_cve_id("CVE-2023-6229", "CVE-2023-6230", "CVE-2023-6231", "CVE-2023-6232",
                "CVE-2023-6233", "CVE-2023-6234", "CVE-2024-0244");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Canon Printers Multiple Vulnerabilities (CP2024-001)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_canon_printer_consolidation.nasl");
  script_mandatory_keys("canon/printer/detected");

  script_tag(name:"summary", value:"Multiple vulnerabilities have been identified for certain Canon
  Small Office Multifunction Printers and Laser Printers.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"These vulnerabilities indicate the possibility that, if a
  product is connected directly to the Internet without using a router (wired or Wi-Fi), an
  unauthenticated remote attacker may be able to execute arbitrary code and/or may be able to
  target the product in a Denial of Service (DoS) attack via the Internet.");

  script_tag(name:"affected", value:"Canon Printers LBP670C Series, MF750C Series, LBP674C,
  LBP1333C, MF750C Series, MF1333C Series, LBP673Cdw, C1333P, MF750C Series and C1333i Series
  firmware version 03.07 and prior.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://psirt.canon/advisory-information/cp2024-001/");
  script_xref(name:"URL", value:"https://www.usa.canon.com/support/canon-product-advisories/Service-Notice-Regarding-Vulnerability-Measure-Against-Buffer-Overflow-for-Laser-Printers-and-Small-Office-Multifunctional-Printers");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:canon:lbp670c_firmware",
                     "cpe:/o:canon:mf750c_firmware",
                     "cpe:/o:canon:lbp674c_firmware",
                     "cpe:/o:canon:lbp1333c_firmware",
                     "cpe:/o:canon:mf750c_firmware",
                     "cpe:/o:canon:mf1333c_firmware",
                     "cpe:/o:canon:lbp673cdw_firmware",
                     "cpe:/o:canon:c1333p_firmware",
                     "cpe:/o:canon:mf750c_firmware",
                     "cpe:/o:canon:c1333i_firmware");

if (!infos = get_app_port_from_list(cpe_list: cpe_list, first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "03.07")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
