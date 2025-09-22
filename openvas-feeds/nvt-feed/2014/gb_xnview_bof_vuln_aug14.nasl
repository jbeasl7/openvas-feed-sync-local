# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xnview:xnview";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804822");
  script_version("2023-07-27T05:05:09+0000");
  script_cve_id("CVE-2012-4988");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-08-26 10:14:25 +0530 (Tue, 26 Aug 2014)");
  script_name("XnView JPEG-LS Image Processing Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"XnView is prone to a buffer overflow vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw exists due to improper bounds checking when processing JPEG-LS
(lossless compression) images.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to potentially execute
arbitrary code on the target machine.");
  script_tag(name:"affected", value:"XnView versions 1.99 and 1.99.1");
  script_tag(name:"solution", value:"Update to XnView version 1.99.6 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50825");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55787");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027607");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/79030");
  script_xref(name:"URL", value:"http://www.reactionpenetrationtesting.co.uk/xnview-jls-heap.html");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Buffer overflow");
  script_dependencies("secpod_xnview_detect_win.nasl");
  script_mandatory_keys("XnView/Win/Ver");
  script_xref(name:"URL", value:"http://www.xnview.com/en");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!version = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:version, test_version:"1.99") ||
   version_is_equal(version:version, test_version:"1.99.1"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
