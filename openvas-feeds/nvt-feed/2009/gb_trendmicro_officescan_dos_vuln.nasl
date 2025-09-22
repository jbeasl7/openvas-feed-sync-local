# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900634");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-05-07 14:39:04 +0200 (Thu, 07 May 2009)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1435");
  script_name("Trend Micro OfficeScan Client Denial Of Service Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34737");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34642");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1146");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/502847/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_trend_micro_office_scan_detect.nasl");
  script_mandatory_keys("Trend/Micro/Officescan/Ver");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation will let the attacker terminate 'NTRtScan.exe' process
  and temporarily disable the real time scanning protection for the system by crafting a directory.");

  script_tag(name:"affected", value:"Trend Micro OfficeScan 8.0 Service Pack 1");

  script_tag(name:"insight", value:"This flaw is due to an error while scanning directories as it fails to
  handle nested directories with excessively long names.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Trend Micro OfficeScan 10 or later.");

  script_tag(name:"summary", value:"Trend Micro OfficeScan Client is prone to a denial of service (DoS) vulnerability.");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("version_func.inc");

key = "SOFTWARE\TrendMicro\NSC\PFW";
if(!registry_key_exists(key:key))
  exit(0);

scanPath = registry_get_sz(key:key, item:"InstallPath");
if(!scanPath)
  exit(0);

scanPath += "PccNTMon.exe";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:scanPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:scanPath);

fileVer = GetVer(file:file, share:share);
if(!fileVer)
  exit(0);

# OfficeScan 8.0 build 3110 and prior (SP1 Patch 1/8.0.0.3110)
if(version_is_less_equal(version:fileVer, test_version:"8.0.0.3110")){
  report = report_fixed_ver(installed_version:fileVer, vulnerable_range:"Less than or equal to 8.0.0.3110", install_path:scanPath);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
