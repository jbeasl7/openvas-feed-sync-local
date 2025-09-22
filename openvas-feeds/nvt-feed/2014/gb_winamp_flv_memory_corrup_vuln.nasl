# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nullsoft:winamp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804826");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2014-3442");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-09-03 15:23:48 +0530 (Wed, 03 Sep 2014)");
  script_name("Winamp '.flv' File Processing Memory Corruption Vulnerability");

  script_tag(name:"summary", value:"Winamp is prone to a memory corruption vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is due to a memory corruption error when handling malicious '.flv'
files.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
service(memory corruption and crash).");
  script_tag(name:"affected", value:"Winamp version 5.666 build 3516 and earlier.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/93173");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67429");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126636");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("General");
  script_dependencies("secpod_winamp_detect.nasl");
  script_mandatory_keys("Winamp/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!version = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less_equal(version:version, test_version:"5.6.6.3516"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
