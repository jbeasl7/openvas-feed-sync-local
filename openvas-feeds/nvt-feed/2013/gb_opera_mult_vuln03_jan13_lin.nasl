# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803145");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2012-6461", "CVE-2012-6462", "CVE-2012-6463", "CVE-2012-6464",
                "CVE-2012-6465", "CVE-2012-6466", "CVE-2012-6467");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-01-07 16:09:01 +0530 (Mon, 07 Jan 2013)");
  script_name("Opera Multiple Vulnerabilities-03 (Jan 2013) - Linux");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1034/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56407");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57120");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57121");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57132");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1035/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1033/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1032/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1031/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1030/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1029/");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/unified/1210/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_mandatory_keys("Opera/Linux/Version");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker crash the browser leading to
  denial of service, execute the arbitrary code or disclose the information.");

  script_tag(name:"affected", value:"Opera version before 12.10 on Linux");

  script_tag(name:"insight", value:"- Internet shortcuts used for phishing in '<img>' elements.

  - Specially crafted WebP images can be used to disclose random chunks
    of memory.

  - Specially crafted SVG images can allow execution of arbitrary code.

  - Cross domain access to object constructors can be used to facilitate
    cross-site scripting.

  - Data URIs can be used to facilitate Cross-Site Scripting.

  - CORS requests can incorrectly retrieve contents of cross origin pages.

  - Certificate revocation service failure may cause Opera to show an
    unverified site as secure.");

  script_tag(name:"solution", value:"Upgrade to Opera version 12.10 or later.");

  script_tag(name:"summary", value:"Opera is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Linux/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"12.10")){
  report = report_fixed_ver(installed_version:operaVer, fixed_version:"12.10");
  security_message(port: 0, data: report);
}
