# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:workstation";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808109");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2016-2077");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-01 03:08:00 +0000 (Thu, 01 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-06-03 17:28:34 +0530 (Fri, 03 Jun 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("VMware Workstation Privilege Escalation Vulnerability (Jun 2016) - Windows");

  script_tag(name:"summary", value:"VMware Workstation is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to incorrectly accessing an executable file.");

  script_tag(name:"impact", value:"Successful exploitation will allow host OS users to gain host OS
  privileges.");

  script_tag(name:"affected", value:"VMware Workstation version 11.x before 11.1.3.");

  script_tag(name:"solution", value:"Update to version 11.1.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0005.html");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Privilege escalation");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(vers =~ "^11\." && version_is_less(version:vers, test_version:"11.1.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"11.1.3");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);