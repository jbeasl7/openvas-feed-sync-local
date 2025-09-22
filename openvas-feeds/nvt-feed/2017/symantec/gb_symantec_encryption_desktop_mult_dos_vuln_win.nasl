# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:encryption_desktop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812049");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2017-13682", "CVE-2017-13679");
  script_tag(name:"cvss_base", value:"2.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-11-02 17:20:00 +0530 (Thu, 02 Nov 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Symantec Encryption Desktop Multiple DoS Vulnerabilities - Windows");

  script_tag(name:"summary", value:"Symantec Encryption Desktop is prone to multiple denial of service (DoS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to a kernel memory leak
  that can occur when a computer program incorrectly manages memory allocations
  in such a way that memory which is no longer needed is not released. In
  object-oriented programming, a memory leak may happen when an object is stored
  in memory but cannot be accessed by the running code.Also there exists additional
  flaw which allows particular machine or network resource unavailable to its intended
  users by temporarily or indefinitely disrupting services of a specific host within
  a network");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to cause denial-of-service conditions.");

  script_tag(name:"affected", value:"Symantec Encryption Desktop prior to
  version 10.4.1 MP2HF1");

  script_tag(name:"solution", value:"Upgrade to Symantec Encryption Desktop
  version 10.4.1 MP2HF1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20171009_00#_Symantec_Encryption_Desktop");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101497");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101090");

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_pgp_desktop_detect_win.nasl");
  script_mandatory_keys("PGPDesktop_or_EncryptionDesktop/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!symanVer = get_app_version(cpe:CPE)){
  exit(0);
}

## 10.4.1MP2 == 10.4.1.759
if(version_is_less_equal(version:symanVer, test_version:"10.4.1.759"))
{
  report = report_fixed_ver(installed_version:symanVer, fixed_version:"10.4.1 MP2HF1");
  security_message(data:report);
  exit(0);
}
exit(0);
