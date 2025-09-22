# SPDX-FileCopyrightText: 2002 Michael Scheidell
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10945");
  script_version("2024-02-09T05:06:25+0000");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-08 19:24:03 +0000 (Thu, 08 Feb 2024)");
  script_cve_id("CVE-2002-0051");
  script_name("Opening Group Policy Files (Q318089)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 Michael Scheidell");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"summary", value:"Windows 2000 allows local users to prevent the application
  of new group policy settings by opening Group Policy files with exclusive-read access.");

  script_tag(name:"impact", value:"Attacker could block application of Group Policy");

  script_tag(name:"affected", value:"- Microsoft Windows 2000 Server

  - Microsoft Windows 2000 Advanced Server

  - Microsoft Windows 2000 Datacenter Server");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-016");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4438");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("secpod_reg.inc");

if ( hotfix_check_domain_controler() <= 0 ) exit(0);
if ( hotfix_check_sp(win2k:3) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q318593") > 0 )
  security_message(port:0);
