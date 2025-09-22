# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:realnetworks:realplayer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804619");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2014-3444");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-06-06 18:25:49 +0530 (Fri, 06 Jun 2014)");
  script_name("RealNetworks RealPlayer '.3gp' Memory Corruption Vulnerability (Jun 2014) - Windows");

  script_tag(name:"summary", value:"RealPlayer is prone to a memory corruption vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw is due to input not being properly sanitized when handling a specially
crafted 3GP file.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to corrupt memory, causing
a denial of service or potentially allowing the execution of arbitrary code.");
  script_tag(name:"affected", value:"RealNetworks RealPlayer version 16.0.3.51 and before on Windows.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126637");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67434");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("gb_realplayer_detect_win.nasl");
  script_mandatory_keys("RealPlayer/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!realVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:realVer, test_version:"16.0", test_version2:"16.0.3.51"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
