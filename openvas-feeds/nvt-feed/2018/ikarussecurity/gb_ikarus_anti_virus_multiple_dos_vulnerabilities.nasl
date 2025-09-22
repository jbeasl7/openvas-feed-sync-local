# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112158");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2017-17804", "CVE-2017-17795", "CVE-2017-17797");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-03 14:55:00 +0000 (Wed, 03 Jan 2018)");
  script_tag(name:"creation_date", value:"2018-01-04 09:32:01 +0100 (Thu, 04 Jan 2018)");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2018 Greenbone AG");

  script_name("IKARUS anti.virus Multiple Denial of Service/BSOD Vulnerabilities");

  script_tag(name:"summary", value:"IKARUS anti.virus is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In IKARUS anti.virus, various driver files allow local users to cause a denial of service (BSOD)
  or possibly have unspecified other impact because of not validating input values correctly.");

  script_tag(name:"affected", value:"IKARUS anti.virus up to and including version 2.16.20.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://github.com/rubyfly/IKARUS_POC/tree/master/0x83000058");
  script_xref(name:"URL", value:"https://github.com/rubyfly/IKARUS_POC/tree/master/0x83000084");
  script_xref(name:"URL", value:"https://github.com/rubyfly/IKARUS_POC/tree/master/0x83000088");

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

if(version_is_less_equal(version:ver, test_version:"2.16.20")) {
  report = report_fixed_ver(installed_version:ver, fixed_version:"None Available");
  security_message(data:report);
  exit(0);
}

exit(99);
