# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:workstation";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806760");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2014-8370", "CVE-2015-1043", "CVE-2015-1044", "CVE-2015-2341");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-05-20 09:35:33 +0530 (Fri, 20 May 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("VMware Workstation Multiple Vulnerabilities (May 2016) - Linux");

  script_tag(name:"summary", value:"VMware Workstation is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An arbitrary file write issue.

  - An input validation issue in the Host Guest File System (HGFS).

  - An input validation issue in VMware Authorization process (vmware-authd).

  - An input validation issue on an RPC command.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  attacker for privilege escalation and to cause a DoS.");

  script_tag(name:"affected", value:"VMware Workstation 10.x prior to version
  10.0.5 on Linux.");

  script_tag(name:"solution", value:"Upgrade to VMware Workstation version
  10.0.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2015-0001.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72338");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72337");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72336");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75094");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2015-0004.html");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_vmware_prdts_detect_lin.nasl");
  script_mandatory_keys("VMware/Linux/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vmwareVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(vmwareVer =~ "^10\.")
{
  if(version_is_less(version:vmwareVer, test_version:"10.0.5"))
  {
    report = report_fixed_ver(installed_version:vmwareVer, fixed_version:"10.0.5");
    security_message(data:report );
    exit(0);
  }
}