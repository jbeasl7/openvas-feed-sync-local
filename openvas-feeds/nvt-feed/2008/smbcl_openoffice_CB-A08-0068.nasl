# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.90030");
  script_version("2024-02-08T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2008-09-09 22:57:12 +0200 (Tue, 09 Sep 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-08 02:18:21 +0000 (Thu, 08 Feb 2024)");
  script_cve_id("CVE-2008-2152", "CVE-2008-3282");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/29622");
  script_name("OpenOffice.org <= 2.4.1 Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_openoffice_detect_win.nasl");
  script_mandatory_keys("OpenOffice/Win/Ver");
  script_tag(name:"solution", value:"All OpenOffice.org users should upgrade to the latest version:");
  script_tag(name:"summary", value:"The remote host is probably affected by the vulnerabilities described in
  CVE-2008-2152 or CVE-2008-3282 on 64-bit platform's

  Impact
   CVE-2008-2152
     Integer overflow in the rtl_allocateMemory function in
     sal/rtl/source/alloc_global.c in OpenOffice.org (OOo)
     2.0 through 2.4 allows remote attackers to execute
     arbitrary code via a crafted file that triggers a
     heap-based buffer overflow.
   CVE-2008-3282
     Integer overflow in the rtl_allocateMemory function
     in sal/rtl/source/alloc_global.c in the memory allocator
     in OpenOffice.org (OOo) 2.4.1, on 64-bit platforms, allows
     remote attackers to cause a denial of service (application
     crash) or possibly execute arbitrary code via a crafted
     document, related to a 'numeric truncation error, ' a
     different vulnerability than CVE-2008-2152.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

openVer = get_kb_item("OpenOffice/Win/Ver");
if(openVer != NULL)
{
  if(version_is_less_equal(version:openVer, test_version:"2.4.1")){
    report = report_fixed_ver(installed_version:openVer, vulnerable_range:"Less than or equal to 2.4.1");
    security_message(port: 0, data: report);
  }
}
