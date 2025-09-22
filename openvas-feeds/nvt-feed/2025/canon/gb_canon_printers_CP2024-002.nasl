# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:canon:";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.171371");
  script_version("2025-04-07T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-04-07 05:39:52 +0000 (Mon, 07 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-04-02 12:58:00 +0000 (Wed, 02 Apr 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2024-2184");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Canon Printers Buffer Overflow Vulnerability (CP2024-002)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_canon_printer_consolidation.nasl");
  script_mandatory_keys("canon/printer/detected");

  script_tag(name:"summary", value:"A buffer overflow vulnerability have been identified for
  certain Canon Small Office Multifunction Printers and Laser Printers.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"This vulnerability indicates the possibility that, if a product
  is connected directly to the Internet without using a router (wired or Wi-Fi), an unauthenticated
  remote attacker may be able to execute arbitrary code and/or may be able to target the product in
  a Denial-of-Service (DoS) attack via the Internet.");

  script_tag(name:"solution", value:"See the referenced advisory for a solution.");

  script_xref(name:"URL", value:"https://psirt.canon/advisory-information/cp2024-002/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (cpe =~ "^cpe:/o:canon:lbp6[26]" || cpe =~ "^cpe:/o:canon:i-sensys_lbp6[26]" ||
    cpe =~ "^cpe:/o:canon:lbp1127c" || cpe =~ "^cpe:/o:canon:c1127p") {
  if (version_is_less_equal(version: version, test_version: "12.07")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:canon:lbp67" || cpe =~ "^cpe:/o:canon:i-sensys_lbp67" ||
    cpe =~ "^cpe:/o:canon:lbp1333c" || cpe =~ "^cpe:/o:canon:c1333p") {
  if (version_is_less_equal(version: version, test_version: "03.09")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:canon:mf[67]4" || cpe =~ "^cpe:/o:canon:i-sensys_mf[67]4" ||
    cpe =~ "^cpe:/o:canon:mf1127c" || cpe =~ "^cpe:/o:canon:c1127i") {
  if (version_is_less_equal(version: version, test_version: "12.07")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:canon:mf75" || cpe =~ "^cpe:/o:canon:i-sensys_mf75" ||
    cpe =~ "^cpe:/o:canon:mf1333c" || cpe =~ "^cpe:/o:canon:c1333i") {
  if (version_is_less_equal(version: version, test_version: "03.09")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
