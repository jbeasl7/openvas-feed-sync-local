# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801131");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-11-02 14:39:30 +0100 (Mon, 02 Nov 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3370", "CVE-2009-3373", "CVE-2009-3372", "CVE-2009-0689",
                "CVE-2009-3374", "CVE-2009-3375", "CVE-2009-3376", "CVE-2009-3380");
  script_name("Mozilla Firefox Multiple Vulnerabilities (Nov 2009) - Linux");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2009-35/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36851");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36853");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36855");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36856");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36857");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36858");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36867");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36871");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-52.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-55.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-56.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-57.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-59.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-61.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-62.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");
  script_tag(name:"impact", value:"Successful exploitation will let attacker to disclose sensitive information,
  bypass certain security restrictions, manipulate certain data, or compromise
  a user's system.");
  script_tag(name:"affected", value:"Mozilla Firefox version 3.0 before 3.0.15 and 3.5 before 3.5.4.");
  script_tag(name:"insight", value:"Multiple flaws are due to following errors:

  - An array indexing error exists when allocating space for floating point
    numbers. This can be exploited to trigger a memory corruption when a
    specially crafted floating point number is processed.

  - An error in the form history functionality can be exploited to disclose
    history entries via a specially crafted web page that triggers the automatic
    filling of form fields.

  - When parsing regular expressions used in Proxy Auto-configuration. This can
    be exploited to cause a crash or potentially execute arbitrary code via
    specially crafted configured PAC files.

  - When processing GIF, color maps can be exploited to cause a heap based
    buffer overflow and potentially execute arbitrary code via a specially
    crafted GIF file.

  - An error in the 'XPCVariant::VariantDataToJS()' XPCOM utility, which can be
    exploited to execute arbitrary JavaScript code with chrome privileges.

  - An error in the implementation of the JavaScript 'document.getSelection()'
    can be exploited to read text selected on a web page in a different domain.

  - An error when downloading files can be exploited to display different file
    names in the download dialog title bar and download dialog body. This can
    be exploited to obfuscate file names via a right-to-left override character
    and potentially trick a user into running an executable file.");
  script_tag(name:"solution", value:"Update to version 3.0.15, 3.5.4 or later.");
  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version:version, test_version:"3.0", test_version2:"3.0.14") ||
   version_in_range(version:version, test_version:"3.5", test_version2:"3.5.3")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"3.0.15/3.5.4", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
