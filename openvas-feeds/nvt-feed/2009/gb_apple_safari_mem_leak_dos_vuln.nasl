# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800100");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-01-13 15:40:34 +0100 (Tue, 13 Jan 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-5821");
  script_name("Apple Safari WebKit Property Memory Leak Remote DoS Vulnerability");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/0812-exploits/safari_webkit_ml.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33080");
  script_xref(name:"URL", value:"http://jbrownsec.blogspot.com/2008/12/new-year-research-are-upon-us.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_apple_safari_smb_login_detect.nasl");
  script_mandatory_keys("apple/safari/smb-login/detected");

  script_tag(name:"affected", value:"Apple Safari 3.2 and prior on Windows (Any).");

  script_tag(name:"insight", value:"The flaw is due to WebKit library which fails to validate the user
  input via a long ALINK attribute in a BODY element in an HTML document.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Apple Safari web browser is prone to denial of service.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to execute arbitrary code
  or can even crash the browser.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"3.525.26.13")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"None", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
