# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900517");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-03-20 07:08:52 +0100 (Fri, 20 Mar 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0914", "CVE-2009-0915", "CVE-2009-0916");
  script_name("Opera Web Browser Multiple Vulnerabilities - Linux");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34135");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33961");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/linux/964");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_mandatory_keys("Opera/Linux/Version");
  script_tag(name:"impact", value:"Successful remote attack could inject arbitrary HTML and script code, launch
  cross site scripting attacks on user's browser session when malicious data
  is being viewed.");
  script_tag(name:"affected", value:"Opera version prior to 9.64 on Linux.");
  script_tag(name:"insight", value:"- memory corruption error when processing a malformed JPEG image.

  - an error related to plug-ins.

  - error with unknown impact and attack vectors related to a
    'moderately severe issue'.");
  script_tag(name:"solution", value:"Upgrade to Opera 9.64.");
  script_tag(name:"summary", value:"Opera Web Browser is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Linux/Version");
if(!operaVer)
  exit(0);

if(version_is_less(version:operaVer, test_version:"9.64")){
  report = report_fixed_ver(installed_version:operaVer, fixed_version:"9.64");
  security_message(port: 0, data: report);
}
