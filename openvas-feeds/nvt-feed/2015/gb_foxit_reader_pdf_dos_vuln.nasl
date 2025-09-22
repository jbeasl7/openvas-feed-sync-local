# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805361");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-2790");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-04-07 18:04:50 +0530 (Tue, 07 Apr 2015)");
  script_name("Foxit Reader Denial of Service Vulnerability");

  script_tag(name:"summary", value:"Foxit Reader is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to Ubyte Size in a
  DataSubBlock structure or LZWMinimumCodeSize in a GIF image.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial-of-service attacks.");

  script_tag(name:"affected", value:"Foxit Reader version prior to
  7.1.");

  script_tag(name:"solution", value:"Upgrade to Foxit Reader version
  7.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1031877");
  script_xref(name:"URL", value:"http://www.foxitsoftware.com/support/security_bulletins.php#FRD-23");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl");
  script_mandatory_keys("foxit/reader/ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!foxitVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:foxitVer, test_version:"7.1.0.0"))
{
  report = 'Installed version: ' + foxitVer + '\n' +
           'Fixed version:     7.1'  + '\n';
  security_message(data:report);
  exit(0);
}

exit(99);
