# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:znc:znc";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124673");
  script_version("2024-07-10T14:21:44+0000");
  script_tag(name:"last_modification", value:"2024-07-10 14:21:44 +0000 (Wed, 10 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-07-08 07:16:42 +0000 (Mon, 08 Jul 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2024-39844");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ZNC < 1.9.1 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_znc_consolidation.nasl");
  script_mandatory_keys("znc/detected");

  script_tag(name:"summary", value:"ZNC is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Remote code execution can occur in modtcl via a KICK.");

  script_tag(name:"affected", value:"ZNC prior to version 1.9.1.");

  script_tag(name:"solution", value:"Update to version 1.9.1 or later.");

  script_xref(name:"URL", value:"https://github.com/znc/znc/releases/tag/znc-1.9.1");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "1.9.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.9.1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
