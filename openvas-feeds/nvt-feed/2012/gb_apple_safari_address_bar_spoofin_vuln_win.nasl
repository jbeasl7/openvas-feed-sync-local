# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802818");
  script_version("2025-09-16T05:38:45+0000");
  script_cve_id("CVE-2011-3844");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2012-03-13 18:17:52 +0530 (Tue, 13 Mar 2012)");
  script_name("Apple Safari 'setInterval()' Address Bar Spoofing Vulnerability - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44976");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52323");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026775");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/73712");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_apple_safari_smb_login_detect.nasl");
  script_mandatory_keys("apple/safari/smb-login/detected");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to conduct spoofing attacks via a
  crafted HTML document.");

  script_tag(name:"affected", value:"Apple Safari version 5.0.5 on Windows.");

  script_tag(name:"insight", value:"The flaw is due to an improper implementation of the setInterval
  function, which allows remote attackers to spoof the address bar via a crafted web page.");

  script_tag(name:"solution", value:"Upgrade to Apple Safari version 5.1.2 or later.");

  script_tag(name:"summary", value:"Apple Safari web browser is prone to address bar spoofing vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"5.33.21.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"Safari 5.1.2 (output of installed version differ from actual Safari version)", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
