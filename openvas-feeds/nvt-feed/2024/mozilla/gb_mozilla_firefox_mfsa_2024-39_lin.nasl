# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2024.39");
  script_cve_id("CVE-2023-6870", "CVE-2024-8381", "CVE-2024-8382", "CVE-2024-8383", "CVE-2024-8384", "CVE-2024-8385", "CVE-2024-8386", "CVE-2024-8387", "CVE-2024-8389");
  script_tag(name:"creation_date", value:"2024-09-06 08:09:10 +0000 (Fri, 06 Sep 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-04 15:50:02 +0000 (Wed, 04 Sep 2024)");

  script_name("Mozilla Firefox Security Advisory (MFSA2024-39) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2024-39");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-39/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1857607%2C1911858%2C1914009");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1907230%2C1909367");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1906744");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1907032");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1908496");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1909163");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1909529");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1911288");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1911909");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1912715");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2024-8385: WASM type confusion involving ArrayTypes
A difference in the handling of StructFields and ArrayTypes in WASM could be used to trigger an exploitable type confusion vulnerability.

CVE-2024-8381: Type confusion when looking up a property name in a 'with' block
A potentially exploitable type confusion could be triggered when looking up a property name on an object being used as the with environment.

CVE-2024-8382: Internal event interfaces were exposed to web content when browser EventHandler listener callbacks ran
Internal browser event interfaces were exposed to web content when privileged EventHandler listener callbacks ran for those events. Web content that tried to use those interfaces would not be able to use them with elevated privileges, but their presence would indicate certain browser features had been used, such as when a user opened the Dev Tools console.

CVE-2024-8383: Firefox did not ask before openings news: links in an external application
Firefox normally asks for confirmation before asking the operating system to find an application to handle a scheme that the browser does not support. It did not ask before doing so for the Usenet-related schemes news: and snews:. Since most operating systems don't have a trusted newsreader installed by default, an unscrupulous program that the user downloaded could register itself as a handler. The website that served the application download could then launch that application at will.

CVE-2024-8384: Garbage collection could mis-color cross-compartment objects in OOM conditions
The JavaScript garbage collector could mis-color cross-compartment objects if OOM conditions were detected at the right point between two passes. This could have led to memory corruption.

CVE-2024-8386: SelectElements could be shown over another site if popups are allowed
If a site had been granted the permission to open popup windows, it could cause Select elements to appear on top of another site to perform a spoofing attack.

CVE-2024-8387: Memory safety bugs fixed in Firefox 130, Firefox ESR 128.2, and Thunderbird 128.2
Memory safety bugs present in Firefox 129, Firefox ESR 128.1, and Thunderbird 128.1. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 130.");

  script_tag(name:"solution", value:"The vendor has released an update. Please see the reference(s) for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "130")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "130", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
