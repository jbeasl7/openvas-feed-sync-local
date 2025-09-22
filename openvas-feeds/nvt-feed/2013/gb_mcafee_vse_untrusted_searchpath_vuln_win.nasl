# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803322");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2009-5118");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-02-21 19:41:20 +0530 (Thu, 21 Feb 2013)");
  script_name("McAfee VirusScan Enterprise Untrusted Search Path Vulnerability - Windows");
  script_xref(name:"URL", value:"http://cxsecurity.com/cveshow/CVE-2009-5118");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45080");
  script_xref(name:"URL", value:"http://www.naked-security.com/cve/CVE-2009-5118");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mcafee_virusscan_enterprise_detect_win.nasl");
  script_mandatory_keys("McAfee/VirusScan/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
code via a crafted document embedded with ActiveX control.");
  script_tag(name:"affected", value:"McAfee VirusScan Enterprise versions prior to 8.7i");
  script_tag(name:"insight", value:"Flaw is due to loading dynamic-link libraries (DLL) from an
untrusted path.");
  script_tag(name:"solution", value:"Apply HF669863 patch for version 8.5i or
Upgrade to version 8.7i or later.");
  script_tag(name:"summary", value:"McAfee VirusScan Enterprise is prone to untrusted search path vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.mcafee.com");
  exit(0);
}

include("version_func.inc");

version = get_kb_item("McAfee/VirusScan/Win/Ver");
if(version)
{
  if(version_is_less(version:version, test_version:"8.7i"))
  {
    report = report_fixed_ver(installed_version:version, fixed_version:"8.7i");
    security_message(port: 0, data: report);
    exit(0);
  }
}
