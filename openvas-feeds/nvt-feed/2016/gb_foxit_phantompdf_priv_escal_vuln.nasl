# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:phantompdf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807561");
  script_version("2024-11-22T15:40:47+0000");
  script_cve_id("CVE-2015-8843");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-19 03:51:00 +0000 (Tue, 19 Apr 2016)");
  script_tag(name:"creation_date", value:"2016-04-25 16:44:43 +0530 (Mon, 25 Apr 2016)");
  script_name("Foxit PhantomPDF Local Privilege Escalation Vulnerability");

  script_tag(name:"summary", value:"Foxit PhantomPDF is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in
  FoxitCloudUpdateService service which can trigger a memory corruption condition
  by writing certain data to a shared memory region.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute code under the context of system.");

  script_tag(name:"affected", value:"Foxit PhantomPDF version 7.2.0.722
  and earlier.");

  script_tag(name:"solution", value:"Upgrade to Foxit PhantomPDF version
  7.2.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-640");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Privilege escalation");
  script_dependencies("gb_foxit_phantom_reader_detect.nasl");
  script_mandatory_keys("foxit/phantompdf/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!foxitVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Foxit PhantomPDF version 7.2.2 = 7.2.2.929
if(version_is_less_equal(version:foxitVer, test_version:"7.2.0.722"))
{
  report = report_fixed_ver(installed_version:foxitVer, fixed_version:"7.2.2.929");
  security_message(data:report);
  exit(0);
}
