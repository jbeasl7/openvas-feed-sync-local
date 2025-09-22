# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802595");
  script_version("2024-02-22T14:37:29+0000");
  script_cve_id("CVE-2011-3960", "CVE-2011-3959", "CVE-2011-3958", "CVE-2011-3957",
                "CVE-2011-3972", "CVE-2011-3956", "CVE-2011-3971", "CVE-2011-3955",
                "CVE-2011-3970", "CVE-2011-3954", "CVE-2011-3969", "CVE-2011-3953",
                "CVE-2011-3968", "CVE-2011-3967", "CVE-2011-3966", "CVE-2011-3965",
                "CVE-2011-3964", "CVE-2011-3963", "CVE-2011-3962", "CVE-2011-3961");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-22 14:37:29 +0000 (Thu, 22 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-02-14 17:13:43 +0530 (Tue, 14 Feb 2012)");
  script_name("Google Chrome < 17.0.963.46 Multiple Vulnerabilities (Feb 2012) - Linux");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47938/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51911");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026654");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2012/02/stable-channel-update.html");

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser or cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 17.0.963.46 on Linux");
  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 17.0.963.46 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

chromeVer = get_kb_item("Google-Chrome/Linux/Ver");
if(isnull(chromeVer)){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"17.0.963.46")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"17.0.963.46");
  security_message(port:0, data:report);
}
