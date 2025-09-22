# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801753");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-03-04 14:32:35 +0100 (Fri, 04 Mar 2011)");
  script_cve_id("CVE-2011-0323", "CVE-2011-0324");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Topaz Systems SigPlus Pro ActiveX Control Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42800");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46128");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/65117");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2011-1/");

  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_sigplus_pro_activex_detect.nasl");
  script_mandatory_keys("SigPlus/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to create or overwrite
  arbitrary local files and to execute arbitrary code.");
  script_tag(name:"affected", value:"Topaz Systems SigPlus Pro ActiveX Control Version 3.95");
  script_tag(name:"insight", value:"The flaws are due to

  - A boundary error when processing the 'KeyString' property which can be
    exploited to cause a heap-based buffer overflow via an overly long string.

  - A boundary error when processing the 'SetLocalIniFilePath()' method, and
    'SetTabletPortPath()' method can be exploited to cause a heap-based buffer
    overflow via an overly long string passed in the 'NewPath' and 'NewPortPath'
    parameter respectively.

  - An unsafe 'SetLogFilePath()' method creating a log file in a specified
    location which can be exploited in combination with the 'SigMessage()'
    method to create an arbitrary file with controlled content.");
  script_tag(name:"solution", value:"Upgrade to the Topaz Systems SigPlus Pro ActiveX Control Version 4.29
  or later.");
  script_tag(name:"summary", value:"SigPlus Pro ActiveX Control is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.topazsystems.com/Software/download/sigplusactivex.htm");
  exit(0);
}


include("version_func.inc");

sigVer = get_kb_item("SigPlus/Ver");
if(!sigVer){
  exit(0);
}

if(version_is_equal(version:sigVer, test_version:"3.95")){
  report = report_fixed_ver(installed_version:sigVer, vulnerable_range:"Equal to 3.95");
  security_message(port: 0, data: report);
}
