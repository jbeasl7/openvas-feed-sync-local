# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805943");
  script_version("2025-06-09T05:41:14+0000");
  script_cve_id("CVE-2015-5380");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-06-09 05:41:14 +0000 (Mon, 09 Jun 2025)");
  script_tag(name:"creation_date", value:"2015-08-04 18:22:15 +0530 (Tue, 04 Aug 2015)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Node.js 'V8 utf-8 decoder' DoS Vulnerability - Windows");

  script_tag(name:"summary", value:"Node.js is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in
  'Utf8DecoderBase::WriteUtf16Slow' function in unicode-decoder.cc within Google
  V8 which does not verify that there is memory available for a UTF-16 surrogate
  pair.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct denial of service attack.");

  script_tag(name:"affected", value:"Node.js before version 0.12.6");

  script_tag(name:"solution", value:"Upgrade to Node.js version 0.12.6 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://blog.nodejs.org/2015/07/03/node-v0-12-6-stable");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75556");
  script_xref(name:"URL", value:"https://medium.com/node-js-javascript/important-security-upgrades-for-node-js-and-io-js-8ac14ece5852");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_nodejs_smb_login_detect.nasl");
  script_mandatory_keys("nodejs/smb-login/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!nodejsVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:nodejsVer, test_version:"0.12.6"))
{
  report = 'Installed version: ' + nodejsVer + '\n' +
           'Fixed version:     ' + "0.12.6" + '\n';
  security_message(data:report);
  exit(0);
}
