# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:skype:skype";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809881");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2016-5720");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-01 02:59:00 +0000 (Wed, 01 Feb 2017)");
  script_tag(name:"creation_date", value:"2017-02-03 13:26:18 +0530 (Fri, 03 Feb 2017)");
  script_name("Microsoft Skype DLL Hijacking Vulnerability");

  script_tag(name:"summary", value:"Microsoft Skype is prone to a DLL hijacking vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to Skype looks for a
  specific DLL by dynamically going through a set of predefined directories. One
  of the directory being scanned is the installation directory, and this is exactly
  what is abused in this vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to execute arbitrary code and conduct DLL hijacking
  attacks via a Trojan horse.");

  script_tag(name:"affected", value:"Microsoft Skype prior to 7.30.80.103.");

  script_tag(name:"solution", value:"Upgrade to Microsoft skype Version
  7.30.80.103 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Sep/65");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95859");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_skype_detect_win.nasl");
  script_mandatory_keys("Skype/Win/Ver");
  script_xref(name:"URL", value:"https://www.skype.com/en");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

# Skype 7.30.80.103 the exploit is not working
if(version_is_less(version:ffVer, test_version:"7.30.80.103"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"7.30.80.103");
  security_message(data:report);
  exit(0);
}
