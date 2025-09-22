# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800815");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-06-16 15:11:01 +0200 (Tue, 16 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-10 02:48:38 +0000 (Sat, 10 Feb 2024)");
  script_cve_id("CVE-2009-1681", "CVE-2009-1682", "CVE-2009-1684", "CVE-2009-1685",
                "CVE-2009-1686", "CVE-2009-1687", "CVE-2009-1688", "CVE-2009-1689",
                "CVE-2009-1690", "CVE-2009-1691", "CVE-2009-1693", "CVE-2009-1694",
                "CVE-2009-1695", "CVE-2009-1696", "CVE-2009-1697", "CVE-2009-1698",
                "CVE-2009-1699");
  script_name("Apple Safari Multiple Vulnerabilities - 02 - (Jun 2009) - Windows");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT3613");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35260");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35270");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35271");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35309");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35311");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35315");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35317");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35318");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35319");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35320");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35321");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35322");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35379");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1522");
  script_xref(name:"URL", value:"http://scary.beasts.org/security/CESA-2009-006.html");
  script_xref(name:"URL", value:"http://scary.beasts.org/security/CESA-2009-008.html");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-09-034");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2009/jun/msg00002.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_apple_safari_smb_login_detect.nasl");
  script_mandatory_keys("apple/safari/smb-login/detected");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary code, bypass
  security restrictions, sensitive information disclosure, XSS attacks, execute
  JavaScript code, DoS attack and can cause other attacks.");

  script_tag(name:"affected", value:"Apple Safari version prior to 4.0 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Safari version 4.0.");

  script_tag(name:"summary", value:"Apple Safari Web Browser is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"4.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"Safari 4.0", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
