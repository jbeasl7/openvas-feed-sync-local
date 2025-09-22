# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hp:loadrunner";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810935");
  script_version("2024-06-28T15:38:46+0000");
  script_cve_id("CVE-2016-4359", "CVE-2016-4360", "CVE-2016-4361");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-03 01:29:00 +0000 (Fri, 03 Nov 2017)");
  script_tag(name:"creation_date", value:"2017-04-20 16:22:23 +0530 (Thu, 20 Apr 2017)");
  script_name("HPE LoadRunner Multiple Remote Code Execution and DoS Vulnerabilities");

  script_tag(name:"summary", value:"HPE LoadRunner is prone to multiple remote code execution (RCE)
  and denial of service (DoS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error within the import_csv functionality. The issue lies in the failure
    to restrict file paths sent to an unlink call which allows for the deletion
    of arbitrary files as SYSTEM.

  - An error within mchan.dll when constructing a shared memory file name.
    The issue lies in the failure to validate the size of a user-supplied string
    prior to copying it to a stack-based buffer.

  - A NULL pointer dereference error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to cause a denial-of-service condition and execute arbitrary code
  on affected system.");

  script_tag(name:"affected", value:"HPE LoadRunner versions 11.52 through
  patch 3, 12.00 through patch 1, 12.01 through patch 3, 12.02 through
  patch 2, and 12.50 through patch 3.");

  script_tag(name:"solution", value:"Apply the mitigation actions provided
  in the link mentioned in the reference.");

  script_tag(name:"solution_type", value:"Mitigation");

  script_tag(name:"qod", value:"30");
  script_xref(name:"URL", value:"https://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05157423");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90975");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1036006");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_hpe_loadrunner_detect.nasl");
  script_mandatory_keys("HPE/LoadRunner/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!hpVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Version is coming as 11.52.xx, 12.00.xx etc
## no version change after applying patch
## qod is reduced
if(hpVer =~ "^(11\.52)" ||
   hpVer =~ "^(12\.00)" ||
   hpVer =~ "^(12\.01)" ||
   hpVer =~ "^(12\.02)" ||
   hpVer =~ "^(12\.50)")
{
  report = report_fixed_ver(installed_version:hpVer, fixed_version:"Mitigation");
  security_message(data:report);
  exit(0);
}
