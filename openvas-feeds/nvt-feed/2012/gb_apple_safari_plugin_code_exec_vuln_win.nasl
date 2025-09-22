# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802819");
  script_version("2025-09-16T05:38:45+0000");
  script_cve_id("CVE-2011-3845");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2012-03-19 12:27:04 +0530 (Mon, 19 Mar 2012)");
  script_name("Apple Safari Plugin Unloading Remote Code Execution Vulnerability - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45758");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52325");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/73713");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_apple_safari_smb_login_detect.nasl");
  script_mandatory_keys("apple/safari/smb-login/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary
  code by tricking a user into visiting a specially crafted web page.");

  script_tag(name:"affected", value:"Apple Safari version 5.1.2 on Windows.");

  script_tag(name:"insight", value:"The flaw is due to unloading of plug-ins when navigating to
  a new page, which allows remote attackers to execute arbitrary code via a
  crafted web page while the user interacts with the plug-in.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Apple Safari web browser is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"5.34.52.7")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"None", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
