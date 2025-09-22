# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800835");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-07-12 15:16:55 +0200 (Sun, 12 Jul 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-2419");
  script_name("Apple Safari JavaScript 'Reload()' DoS Vulnerability (Jul 2009)");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51533");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35555");
  script_xref(name:"URL", value:"http://marcell-dietl.de/index/adv_safari_4_x_js_reload_dos.php");
  script_xref(name:"URL", value:"http://trac.webkit.org/changeset/44519");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_apple_safari_smb_login_detect.nasl");
  script_mandatory_keys("apple/safari/smb-login/detected");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary code, and can
  deny the service in the vitim's system.");

  script_tag(name:"affected", value:"Apple Safari version 4.0.2 (4.30.19.1) and prior on Windows.");

  script_tag(name:"insight", value:"The flaw is due to a use-after-free error while calling the
  'servePendingRequests()' function in WebKit.via a crafted HTML document
  that references a zero-length '.js' file and the JavaScript reload function.");

  script_tag(name:"solution", value:"Apply the patch from the referenced WebKit development repository.");

  script_tag(name:"summary", value:"Apple Safari Web Browser is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"4.30.19.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See references", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
