# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901138");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_cve_id("CVE-2010-1778", "CVE-2010-1780", "CVE-2010-1783", "CVE-2010-1782",
                "CVE-2010-1785", "CVE-2010-1784", "CVE-2010-1786", "CVE-2010-1788",
                "CVE-2010-1787", "CVE-2010-1790", "CVE-2010-1789", "CVE-2010-1792",
                "CVE-2010-1791", "CVE-2010-1793", "CVE-2010-1796");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Apple Safari Multiple Vulnerabilities (Jul 2010)");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4276");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42020");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2010/Jul/msg00001.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_apple_safari_smb_login_detect.nasl");
  script_mandatory_keys("apple/safari/smb-login/detected");

  script_tag(name:"impact", value:"Successful exploitation may results in information disclosure, remote code
  execution, denial of service, or other consequences.");

  script_tag(name:"affected", value:"Apple Safari version prior to 5.0.1 (5.33.17.8) on Windows.");

  script_tag(name:"insight", value:"Please see the references for more information about the vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Apple Safari version 5.0.1 or later.");

  script_tag(name:"summary", value:"Apple Safari Web Browser is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"5.33.17.8")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"Safari 5.0.1 (5.33.17.8)", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
