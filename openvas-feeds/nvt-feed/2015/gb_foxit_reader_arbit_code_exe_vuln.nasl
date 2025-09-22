# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806903");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-8580");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-12-31 18:46:31 +0530 (Thu, 31 Dec 2015)");
  script_name("Foxit Reader Arbitrary Code Execution Vulnerability");

  script_tag(name:"summary", value:"Foxit Reader is prone to an arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists within the handling of the
  Print method and App object. A specially crafted PDF document can force a
  dangling pointer to be reused after it has been freed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code via a crafted PDF document.");

  script_tag(name:"affected", value:"Foxit Reader version prior to
  7.2.2.");

  script_tag(name:"solution", value:"Upgrade to Foxit Reader version
  7.2.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php#FRD-34");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl");
  script_mandatory_keys("foxit/reader/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!foxitVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:foxitVer, test_version:"7.2.2"))
{
  report = 'Installed version: ' + foxitVer + '\n' +
           'Fixed version:     7.2.2'  + '\n';
  security_message(data:report);
  exit(0);
}
