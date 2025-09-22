# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817567");
  script_version("2025-01-17T15:39:18+0000");
  script_cve_id("CVE-2020-17008");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2021-01-12 15:51:17 +0530 (Tue, 12 Jan 2021)");
  script_name("Microsoft Windows Kernel Elevation of Privilege Vulnerability (CVE-2020-17008)");

  script_tag(name:"summary", value:"Microsoft Windows is prone to an elevation of privilege
  vulnerability.

  This VT has been deprecated and replaced by the following VTs covering the new CVE-2021-1648:

  - OID: 1.3.6.1.4.1.25623.1.0.817573

  - OID: 1.3.6.1.4.1.25623.1.0.817569

  - OID: 1.3.6.1.4.1.25623.1.0.817568");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to wrong fix of pointers which are simply
  changed to offsets.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to elevate
  privileges.");

  script_tag(name:"affected", value:"- Microsoft Windows 8.1

  - Microsoft Windows Server 2012 R2

  - Microsoft Windows 10 Version 1803

  - Microsoft Windows 10

  - Microsoft Windows 10 Version 1607

  - Microsoft Windows 10 Version 1709

  - Microsoft Windows 10 Version 1809

  - Microsoft Windows 10 Version 1903

  - Microsoft Windows 10 Version 1909

  - Microsoft Windows 10 Version 2004

  - Microsoft Windows Server 2012

  - Microsoft Windows Server 2016

  - Microsoft Windows Server 2019");

  script_tag(name:"solution", value:"The vendor has released updates Please check the referenced
  replacement VTs for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
