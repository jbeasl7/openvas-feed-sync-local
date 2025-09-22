# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:prime_collaboration_provisioning";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811056");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2017-6637", "CVE-2017-6636");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-05-29 13:39:30 +0530 (Mon, 29 May 2017)");
  script_name("Cisco Prime Collaboration Provisioning Multiple Directory Traversal Vulnerabilities (May 2017)");

  script_tag(name:"summary", value:"cisco prime collaboration provisioning is prone to multiple directory traversal vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist as the affected software
  does not perform proper input validation of HTTP requests and fails to apply
  role-based access controls (RBACs) to requested HTTP URLs.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  authenticated, remote attacker to view or delete any file on an affected
  system.");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"affected", value:"Cisco Prime Collaboration Provisioning
  Software Releases 9.0.0, 9.5.0, 10.0.0, 10.5.0, 10.5.1 and 10.6 through 11.0");

  script_tag(name:"solution", value:"Upgrade to Cisco Prime Collaboration
  Provisioning Software Release 11.1 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc99618");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98530");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98526");
  script_xref(name:"URL", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc99604");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170517-pcp5");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170517-pcp4");

  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_cisco_pcp_version.nasl");
  script_mandatory_keys("cisco_pcp/version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe:CPE)) exit(0);

if(version =~ "^((9|10|11)\.)")
{
  if((version == "9.0.0")|| (version == "9.5.0")|| (version == "10.0.0")||
     (version == "10.5.0")||(version == "10.5.1")||(version == "10.6.0")||
     (version == "10.6.2")||(version == "11.0.0"))
  {
    report = report_fixed_ver(installed_version:version, fixed_version:"11.1");
    security_message(data:report);
    exit(0);
  }
}
exit(0);
