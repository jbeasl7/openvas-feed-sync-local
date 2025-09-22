# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:fortinet:fortiweb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105796");
  script_version("2024-11-26T07:35:52+0000");
  script_tag(name:"last_modification", value:"2024-11-26 07:35:52 +0000 (Tue, 26 Nov 2024)");
  script_tag(name:"creation_date", value:"2016-07-05 19:08:43 +0200 (Tue, 05 Jul 2016)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-07-14 15:17:00 +0000 (Thu, 14 Jul 2016)");

  script_cve_id("CVE-2016-5092");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Fortinet FortiWeb Path Traversal Vulnerability (FG-IR-16-009)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("FortiOS Local Security Checks");
  script_dependencies("gb_fortinet_fortiweb_consolidation.nasl");
  script_mandatory_keys("fortinet/fortiweb/detected");

  script_tag(name:"summary", value:"Fortinet FortiWeb is prone to a path traversal
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A path traversal vulnerability allows an administrator account
  with read and write privileges to read arbitrary files using the autolearn feature.");

  script_tag(name:"affected", value:"Fortinet FortiWeb 4.4.6 through 5.5.2 with the autolearn
  feature configured.");

  script_tag(name:"solution", value:"Update to version 5.5.3 or later.");

  script_xref(name:"URL", value:"https://www.fortiguard.com/psirt/FG-IR-16-009");
  script_xref(name:"Advisory-ID", value:"FG-IR-16-009");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "4.4.6", test_version2: "5.5.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.3");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
