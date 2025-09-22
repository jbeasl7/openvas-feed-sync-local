# SPDX-FileCopyrightText: 2002 SECNAP Network Security, LLC
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11177");
  script_version("2024-09-12T07:59:53+0000");
  script_tag(name:"last_modification", value:"2024-09-12 07:59:53 +0000 (Thu, 12 Sep 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"IAVA", value:"2003-B-0002");
  script_cve_id("CVE-2002-0866", "CVE-2002-0867", "CVE-2002-0865", "CVE-2002-1257",
                "CVE-2002-1258", "CVE-2002-1259", "CVE-2002-1260", "CVE-2002-1261",
                "CVE-2002-1325", "CVE-2002-1263", "CVE-2002-1292", "CVE-2002-1295");
  script_name("Microsoft VM Multiple Vulnerabilities (MS02-052, MS02-069)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 SECNAP Network Security, LLC");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"summary", value:"Microsoft Virtual Machine (Microsoft VM) is prone to multiple
  vulnerabilities.");

  script_tag(name:"insight", value:"Without the patch applied from MS02-052 the following flaws
  exist:

  - CVE-2002-0866: DLL execution via JDBC classes

  - CVE-2002-0867: Handle validation flaw

  - CVE-2002-0865: Inappropriate methods exposed in XML support classes

  Without the patch applied from MS02-069 the following flaws exist:

  - CVE-2002-1257: COM Object Access Vulnerability

  - CVE-2002-1258: CODEBASE Spoofing Vulnerabilities

  - CVE-2002-1259: Domain Spoofing Vulnerability

  - CVE-2002-1260: JDBC API Vulnerability

  - CVE-2002-1261: Standard Security Manager Access Vulnerability

  - CVE-2002-1325: User.dir Exposure Vulnerability

  - CVE-2002-1263: Incomplete Java object Instantiation Vulnerability

  - CVE-2002-1292: Package Access Restriction Bypassing Vulnerability

  - CVE-2002-1295: HTML Applet Tag Class Restriction Bypass Vulnerability");

  script_tag(name:"affected", value:"All builds of the Microsoft VM up to and including build
  5.0.3805 are affected by these vulnerabilities.");

  script_tag(name:"solution", value:"The vendor has releases updates. Please see the references for
  more information.");

  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-069");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-052");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210129003533/http://www.securityfocus.com/bid/6371");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210129003533/http://www.securityfocus.com/bid/6372");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121155633/http://www.securityfocus.com/bid/6133");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121155634/http://www.securityfocus.com/bid/6136");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("secpod_reg.inc");
include("host_details.inc");

if(hotfix_check_sp(xp:2, win2k:4) <= 0)
  exit(0);

if(!version = get_kb_item ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Active Setup/Installed Components/{08B0E5C0-4FCB-11CF-AAA5-00401C608500}/Version"))
  exit(0);

# should be "5,00,3807,0";
v = split(version, sep:",", keep:FALSE);
if(int(v[0]) < 5 ||
   (int(v[0]) == 5 && int(v[1]) == 0 && int(v[2]) < 3809)) {
  if(hotfix_missing(name:"810030") > 0) {
    security_message(port:0);
    exit(0);
  }
}

exit(99);
