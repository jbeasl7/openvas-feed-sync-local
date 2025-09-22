# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:perl:perl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809819");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2016-6185");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-10 13:20:00 +0000 (Thu, 10 Sep 2020)");
  script_tag(name:"creation_date", value:"2016-11-24 21:21:51 +0530 (Thu, 24 Nov 2016)");
  script_name("Perl 'XSLoader Method' Code Execution Vulnerability - Windows");

  script_tag(name:"summary", value:"Perl is prone to a code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to The 'XSLoader::load'
  method in 'XSLoader' in Perl does not properly locate '.so' files when called in
  a string eval.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  local users to execute arbitrary code.");

  script_tag(name:"affected", value:"Perl 5.24.0.24 and before on Windows");

  script_tag(name:"solution", value:"Update Perl to version 5.24.1.2402 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3628");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91685");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/07/07/1");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod", value:"30");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_perl_detect_win.nasl");
  script_mandatory_keys("Perl/Strawberry_or_Active/Installed");
  script_xref(name:"URL", value:"https://www.perl.org");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!perlVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less_equal(version:perlVer, test_version:"5.24.0.24"))
{
  report = report_fixed_ver(installed_version:perlVer, fixed_version:'Ask Vendor for a solution');
  security_message(data:report);
  exit(0);
}
