# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802221");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2011-07-13 17:31:13 +0200 (Wed, 13 Jul 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Citrix Provisioning Services 'streamprocess.exe' Component RCE Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42954");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45914");
  script_xref(name:"URL", value:"http://support.citrix.com/article/CTX127149");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-023/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_citrix_provisioning_services_detect.nasl");
  script_mandatory_keys("Citrix/Provisioning/Services/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code in the context of the SYSTEM user.");
  script_tag(name:"affected", value:"Citrix Provisioning Services version 5.6 and prior.");
  script_tag(name:"insight", value:"The flaw is due to an error in the 'streamprocess.exe' component when
  handling a '0x40020010' type packet. This can be exploited to cause a stack
  based buffer overflow via a specially crafted packet sent to UDP port 6905.");
  script_tag(name:"solution", value:"Upgrade to Citrix Provisioning Services version 5.6 SP1 or later.");
  script_tag(name:"summary", value:"Citrix Provisioning Services is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.citrix.com/article/CTX127123");
  exit(0);
}


include("version_func.inc");

version = get_kb_item("Citrix/Provisioning/Services/Ver");
if(version)
{
  if(version_is_less_equal(version:version, test_version:"5.6.0")){
    report = report_fixed_ver(installed_version:version, vulnerable_range:"Less than or equal to 5.6.0");
    security_message(port: 0, data: report);
  }
}
