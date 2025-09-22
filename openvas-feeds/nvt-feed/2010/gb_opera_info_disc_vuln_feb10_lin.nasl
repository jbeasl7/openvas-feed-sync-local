# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902123");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-02-22 13:34:53 +0100 (Mon, 22 Feb 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-0653");
  script_name("Opera Information Disclosure Vulnerability - Linux");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/390938.php");
  script_xref(name:"URL", value:"http://code.google.com/p/chromium/issues/detail?id=9877");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_mandatory_keys("Opera/Linux/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain sensitive
information via a crafted document.");
  script_tag(name:"affected", value:"Opera version prior to 10.10 on Linux.");
  script_tag(name:"insight", value:"- Opera permits cross-origin loading of CSS stylesheets even when the
stylesheet download has an incorrect MIME type and the stylesheet document
is malformed.");
  script_tag(name:"solution", value:"Update to Opera version 10.10");
  script_tag(name:"summary", value:"Opera Web Browser is prone to an information disclosure vulnerability.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Linux/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"10.10")){
  report = report_fixed_ver(installed_version:operaVer, fixed_version:"10.10");
  security_message(port: 0, data: report);
}
