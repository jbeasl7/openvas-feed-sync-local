# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804128");
  script_version("2025-09-16T05:38:45+0000");
  script_cve_id("CVE-2013-5130");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2013-11-06 11:11:36 +0530 (Wed, 06 Nov 2013)");
  script_name("Apple Safari 'Webkit' Information Disclosure Vulnerability (APPLE-SA-2013-10-22-2) - Windows");

  script_tag(name:"summary", value:"Apple Safari is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to unspecified vulnerability in the Apple
  Safari Webkit.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain browsing
  information by leveraging localstorage/files.");

  script_tag(name:"affected", value:"Apple Safari 5.x and prior on Windows.");

  # nb: Seems to be only fixed on 6.1 but 5.x was the last version on Windows
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://lists.apple.com/archives/security-announce/2013/Oct/msg00003.html");
  script_xref(name:"URL", value:"http://secunia.com/advisories/55448");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63289");

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_apple_safari_smb_login_detect.nasl");
  script_mandatory_keys("apple/safari/smb-login/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"5.34.57.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"None", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
