# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902955");
  script_version("2025-03-05T05:38:53+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-0074");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-28 17:26:06 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2013-03-13 12:40:20 +0530 (Wed, 13 Mar 2013)");
  script_name("Microsoft Silverlight Remote Code Execution Vulnerability (2814124) - Mac OS X");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2814124");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58327");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-022");

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_ms_silverlight_detect_macosx.nasl");
  script_mandatory_keys("MS/Silverlight/MacOSX/Ver");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to execute arbitrary code.");

  script_tag(name:"affected", value:"Microsoft Silverlight version 5 on Mac OS X.");

  script_tag(name:"insight", value:"The flaw is due to a double-free error when rendering a HTML object, which
  can be exploited via a specially crafted Silverlight application.");

  script_tag(name:"solution", value:"The vendor has released an update. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS13-022.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

slightVer = get_kb_item("MS/Silverlight/MacOSX/Ver");

if(!slightVer || slightVer !~ "^5\."){
  exit(0);
}

if(version_in_range(version:slightVer, test_version:"5.0", test_version2:"5.1.20124.0")){
   security_message( port: 0, data: "The target host was found to be vulnerable" );
}
