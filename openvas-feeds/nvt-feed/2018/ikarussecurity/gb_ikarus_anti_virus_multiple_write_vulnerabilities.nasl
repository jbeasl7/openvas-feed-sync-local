# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112157");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2017-14961", "CVE-2017-14962", "CVE-2017-14963", "CVE-2017-14964", "CVE-2017-14965",
                "CVE-2017-14966", "CVE-2017-14967", "CVE-2017-14968", "CVE-2017-14969");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-05 01:20:00 +0000 (Tue, 05 Dec 2017)");
  script_tag(name:"creation_date", value:"2018-01-04 09:34:01 +0100 (Thu, 04 Jan 2018)");
  script_name("IKARUS anti.virus Multiple Arbitrary/Out of Bounds Write Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2018 Greenbone AG");

  script_tag(name:"summary", value:"IKARUS anti.virus is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In IKARUS anti.virus, various drivers contain Arbitrary or Out of Bounds Write vulnerabilities because of not validating input values from various sources.");

  script_tag(name:"affected", value:"IKARUS anti.virus before version 2.16.18.");

  script_tag(name:"solution", value:"Update IKARUS anti.virus to version 2.16.18 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.greyhathacker.net/?p=995");
  script_xref(name:"URL", value:"https://www.ikarussecurity.com/about-ikarus/security-blog/vulnerability-in-windows-antivirus-products-ik-sa-2017-0002/");

  script_dependencies("gb_ikarus_anti_virus_detect.nasl");
  script_mandatory_keys("ikarus/anti.virus/detected", "ikarus/anti.virus/version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:ikarus:anti.virus";

if(!ver = get_app_version(cpe:CPE)) {
  exit(0);
}

if(version_is_less(version:ver, test_version:"2.16.18")) {
  report = report_fixed_ver(installed_version:ver, fixed_version:"2.16.18");
  security_message(data:report);
  exit(0);
}

exit(99);
