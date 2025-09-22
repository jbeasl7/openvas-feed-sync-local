# SPDX-FileCopyrightText: 2010 LSS
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102022");
  script_version("2024-02-05T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-05 05:05:38 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-04-06 10:41:02 +0200 (Tue, 06 Apr 2010)");
  script_name("Safari 4.0.5 Update");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-03 02:24:33 +0000 (Sat, 03 Feb 2024)");
  script_category(ACT_GATHER_INFO);
  script_cve_id("CVE-2010-0044", "CVE-2010-0046", "CVE-2010-0047", "CVE-2010-0048", "CVE-2010-0049",
                "CVE-2010-0050", "CVE-2010-0051", "CVE-2010-0052", "CVE-2010-0053", "CVE-2010-0054");
  script_copyright("Copyright (C) 2010 LSS");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4070");

  script_tag(name:"summary", value:"Installed version of Safari on remote host is older than 4.0.5 and
  contains security vulnerabilities.");

  script_tag(name:"affected", value:"One or more of the following components are affected:

  PubSub, WebKit");

  script_tag(name:"solution", value:"Update Safari to newest version. Please see the references for
  more information.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"4.0.5")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.0.5", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
