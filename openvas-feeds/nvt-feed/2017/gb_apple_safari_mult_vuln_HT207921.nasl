# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811251");
  script_version("2024-02-16T14:37:06+0000");
  script_cve_id("CVE-2017-7060", "CVE-2017-7006", "CVE-2017-7011", "CVE-2017-7018",
                "CVE-2017-7020", "CVE-2017-7030", "CVE-2017-7034", "CVE-2017-7037",
                "CVE-2017-7039", "CVE-2017-7040", "CVE-2017-7041", "CVE-2017-7042",
                "CVE-2017-7043", "CVE-2017-7046", "CVE-2017-7048", "CVE-2017-7052",
                "CVE-2017-7055", "CVE-2017-7056", "CVE-2017-7061", "CVE-2017-7038",
                "CVE-2017-7059", "CVE-2017-7049", "CVE-2017-7064", "CVE-2017-7019",
                "CVE-2017-7012");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 14:37:06 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-22 19:27:00 +0000 (Fri, 22 Mar 2019)");
  script_tag(name:"creation_date", value:"2017-07-20 11:35:58 +0530 (Thu, 20 Jul 2017)");
  script_name("Apple Safari Multiple Vulnerabilities (HT207921)");

  script_tag(name:"summary", value:"Apple Safari is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in the processing of print dialogs in Printing module.

  - An error in painting the cross-origin buffer into the frame in Webkit module.

  - A state management issue due to error in frame handling.

  - Multiple memory corruption issues in WebKit module.

  - A logic issue existed in the handling of DOMParser in WebKit module.

  - A memory initialization issue in WebKit module.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct cross site scripting and address bar spoofing attacks,
  allow cross-origin data to be exfiltrated by using SVG filters to conduct a
  timing side-channel attack, arbitrary code execution, read restricted memory
  and put browser into an infinite number of print dialogs making users believe
  their browser was locked.");

  script_tag(name:"affected", value:"Apple Safari versions before 10.1.2");

  script_tag(name:"solution", value:"Upgrade to Apple Safari 10.1.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT207921");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99887");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99886");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99885");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99888");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99890");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!safVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:safVer, test_version:"10.1.2"))
{
  report = report_fixed_ver(installed_version:safVer, fixed_version:"10.1.2");
  security_message(data:report);
  exit(0);
}
