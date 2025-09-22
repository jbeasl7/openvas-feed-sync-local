# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800047");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2008-10-30 06:53:04 +0100 (Thu, 30 Oct 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-4694", "CVE-2008-4695");
  script_name("Opera Remote Code Execution and Information Disclosure Vulnerabilities - Linux");
  script_xref(name:"URL", value:"http://www.opera.com/support/search/view/901/");
  script_xref(name:"URL", value:"http://www.opera.com/support/search/view/902/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_mandatory_keys("Opera/Linux/Version");

  script_tag(name:"impact", value:"Successful remote attack could inject arbitrary code, launch
  cross site attacks, information disclosure and can even steal related DB (DataBase) contents.");

  script_tag(name:"affected", value:"Opera version prior to 9.60 on Linux.");

  script_tag(name:"insight", value:"Flaws are due to:

  - an error in Opera.dll, that fails to anchor identifier (optional argument)

  - an unknown error predicting the cache pathname of a cached Java
    applet and then launching this applet from the cache.");

  script_tag(name:"solution", value:"Upgrade to Opera 9.60 or later.");

  script_tag(name:"summary", value:"Opera Web Browser is prone to remote code execution and information disclosure Vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Linux/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"9.60")){
  report = report_fixed_ver(installed_version:operaVer, fixed_version:"9.60");
  security_message(port: 0, data: report);
}
