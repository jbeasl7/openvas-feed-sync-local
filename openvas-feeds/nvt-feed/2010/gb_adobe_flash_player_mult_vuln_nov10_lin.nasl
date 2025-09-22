# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801630");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-11-12 15:34:28 +0100 (Fri, 12 Nov 2010)");
  script_cve_id("CVE-2010-3636", "CVE-2010-3637", "CVE-2010-3638", "CVE-2010-3639",
                "CVE-2010-3640", "CVE-2010-3641", "CVE-2010-3642", "CVE-2010-3643",
                "CVE-2010-3644", "CVE-2010-3645", "CVE-2010-3646", "CVE-2010-3647",
                "CVE-2010-3648", "CVE-2010-3649", "CVE-2010-3650", "CVE-2010-3652");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Flash Player Multiple Vulnerabilities - Linux");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41917");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44669");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-26.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code or cause
  a denial of service via unknown vectors.");
  script_tag(name:"affected", value:"Adobe Flash Player version 10.1.85.3 and prior on Linux");
  script_tag(name:"insight", value:"The flaws are caused by unspecified errors, that can be exploited to execute
  arbitrary code or cause a denial of service.");
  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version 10.1.102.64 or later");
  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple unspecified vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

vers = get_kb_item("AdobeFlashPlayer/Linux/Ver");
vers = ereg_replace(pattern:",", string:vers, replace:".");
if(vers) {
  if(version_in_range(version:vers, test_version:"10", test_version2:"10.1.85.3")||
     version_is_less(version:vers, test_version:"9.0.289.0")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
