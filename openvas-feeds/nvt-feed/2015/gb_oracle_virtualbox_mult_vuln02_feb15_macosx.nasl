# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805432");
  script_version("2025-09-19T05:38:25+0000");
  script_cve_id("CVE-2015-0427", "CVE-2014-6595", "CVE-2014-6590", "CVE-2014-6589",
                "CVE-2014-6588");
  script_tag(name:"cvss_base", value:"3.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-02-02 10:11:39 +0530 (Mon, 02 Feb 2015)");
  script_name("Oracle VirtualBox Multiple Vulnerabilities (Feb 2015) - Mac OS X");

  script_tag(name:"summary", value:"Oracle VirtualBox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple
  unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attackers to cause a DoS (Denial of Service) and disclose potentially
  sensitive information.");

  script_tag(name:"affected", value:"Oracle VirtualBox versions 4.3.x prior to 4.3.20
  on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 4.3.20 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.scip.ch/en/?vuldb.68800");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72216");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72206");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72213");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72202");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72196");
  script_xref(name:"URL", value:"http://secunia.com/advisories/62524");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_family("General");
  script_dependencies("secpod_oracle_virtualbox_detect_macosx.nasl");
  script_mandatory_keys("Oracle/VirtualBox/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^4\.3") {
  if(version_is_less(version:vers, test_version:"4.3.20")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"4.3.20", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
