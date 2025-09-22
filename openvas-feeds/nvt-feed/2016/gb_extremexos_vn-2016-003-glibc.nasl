# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:extremenetworks:exos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106427");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2016-11-29 08:20:28 +0700 (Tue, 29 Nov 2016)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-30 21:31:00 +0000 (Fri, 30 Nov 2018)");

  script_cve_id("CVE-2015-7547");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Extreme ExtremeXOS glibc Vulnerability (VN-2016-003)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_extremeos_consolidation.nasl");
  script_mandatory_keys("extreme/exos/detected");

  script_tag(name:"summary", value:"Extreme ExtremeXOS is prone to a vulnerability in glibc.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"ExtremeXOS has a vulnerable version of glibc installed which
  suffers from a stack buffer overflow.");

  script_tag(name:"impact", value:"An attacker may cause a denial of service condition or execute
  arbitrary code.");

  script_tag(name:"affected", value:"Extreme ExtremeXOS version 15.3 through 16.1.x.");

  script_tag(name:"solution", value:"Update to version 15.7.4, 16.2.1 or later.");

  script_xref(name:"URL", value:"https://gtacknowledge.extremenetworks.com/articles/Vulnerability_Notice/VN-2016-003-glibc");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_greater(version: version, test_version: "15.3.1") &&
    version_is_less(version: version, test_version: "15.7.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.7.4");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_is_greater(version: version, test_version: "16.1.1") &&
    version_is_less(version: version, test_version: "16.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.2.1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
