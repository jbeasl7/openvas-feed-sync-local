# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140083");
  script_version("2024-07-12T05:05:45+0000");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-12 05:05:45 +0000 (Fri, 12 Jul 2024)");
  script_tag(name:"creation_date", value:"2016-11-30 13:23:23 +0100 (Wed, 30 Nov 2016)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-01 19:54:00 +0000 (Thu, 01 Dec 2016)");
  script_cve_id("CVE-2016-5685");
  script_name("Dell iDRAC7 and iDRAC8 Devices Code Injection Vulnerability (Nov 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_dell_drac_idrac_consolidation.nasl");
  script_mandatory_keys("dell/idrac/detected");

  script_xref(name:"URL", value:"http://en.community.dell.com/techcenter/extras/m/white_papers/20443326");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94585");

  script_tag(name:"summary", value:"Dell iDRAC7 and iDRAC8 devices allow authenticated users to gain
  Bash shell access through a string injection.");

  script_tag(name:"vuldetect", value:"Checks the firmware version.");

  script_tag(name:"affected", value:"Dell iDRAC7 and iDRAC8 devices with firmware version before
  2.40.40.40.");

  script_tag(name:"solution", value:"Update to firmware version 2.40.40.40 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:dell:idrac7",
                     "cpe:/a:dell:idrac8");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = infos["version"];

if (version_is_less(version: version, test_version: "2.40.40.40")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.40.40.40");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
