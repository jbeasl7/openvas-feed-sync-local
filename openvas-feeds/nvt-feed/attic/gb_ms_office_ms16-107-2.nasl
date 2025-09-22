# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112000");
  script_version("2025-01-17T15:39:18+0000");
  script_cve_id("CVE-2016-0137");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:11:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2017-08-18 14:45:19 +0200 (Fri, 18 Aug 2017)");
  script_name("Microsoft Office 2013 APP-V ASLR Bypass Vulnerability (3118268)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3118268");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92785");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-107");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS16-107.

  This VT has been deprecated and replaced by the VT 'Microsoft Office Suite RCE Vulnerabilities (3185852)'
  (1.3.6.1.4.1.25623.1.0.807361).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An information disclosure vulnerability exists in the way
  that the Click-to-Run (C2R) components handle objects in memory,
  which could lead to an Address Space Layout Randomization (ASLR) bypass.");

  script_tag(name:"impact", value:"Successful exploitation could allow
  remote code execution if a user opens a specially crafted Microsoft Office file.");

  script_tag(name:"affected", value:"Microsoft Office 2013 Service Pack 1.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66); # this VT is deprecated since it has been covered already by gb_ms_office-ms16-107.nasl
