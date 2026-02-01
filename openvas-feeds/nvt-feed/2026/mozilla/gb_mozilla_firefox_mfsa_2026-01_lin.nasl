# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2026.01");
  script_cve_id("CVE-2026-0877", "CVE-2026-0878", "CVE-2026-0879", "CVE-2026-0880", "CVE-2026-0881", "CVE-2026-0882", "CVE-2026-0883", "CVE-2026-0884", "CVE-2026-0885", "CVE-2026-0886", "CVE-2026-0887", "CVE-2026-0888", "CVE-2026-0889", "CVE-2026-0890", "CVE-2026-0891", "CVE-2026-0892");
  script_tag(name:"creation_date", value:"2026-01-13 14:12:56 +0000 (Tue, 13 Jan 2026)");
  script_version("2026-01-14T05:47:41+0000");
  script_tag(name:"last_modification", value:"2026-01-14 05:47:41 +0000 (Wed, 14 Jan 2026)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_origin", value:"Vendor");
  script_tag(name:"severity_date", value:"2026-01-12 23:00:00 +0000 (Mon, 12 Jan 2026)");

  script_name("Mozilla Firefox Security Advisory (MFSA2026-01) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2026-01");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2026-01/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1924125");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1964722%2C2000981%2C2003100%2C2003278");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1985996");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1986912%2C1996718%2C1999633%2C2001081%2C2004443");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1989340");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1999084");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1999257");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=2003588");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=2003607");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=2003989");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=2004602");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=2005014");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=2005081");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=2005658");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=2005845");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=2006500");

  script_tag(name:"summary", value:"The remote host is missing an update for Mozilla Firefox, announced via the advisory MFSA2026-01.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2026-0877: Mitigation bypass in the DOM: Security component

CVE-2026-0878: Sandbox escape due to incorrect boundary conditions in the Graphics: CanvasWebGL component

CVE-2026-0879: Sandbox escape due to incorrect boundary conditions in the Graphics component

CVE-2026-0880: Sandbox escape due to integer overflow in the Graphics component

CVE-2026-0881: Sandbox escape in the Messaging System component

CVE-2026-0882: Use-after-free in the IPC component

CVE-2026-0883: Information disclosure in the Networking component

CVE-2026-0884: Use-after-free in the JavaScript Engine component

CVE-2026-0885: Use-after-free in the JavaScript: GC component

CVE-2026-0886: Incorrect boundary conditions in the Graphics component

CVE-2026-0887: Clickjacking issue, information disclosure in the PDF Viewer component

CVE-2026-0888: Information disclosure in the XML component

CVE-2026-0889: Denial-of-service in the DOM: Service Workers component

CVE-2026-0890: Spoofing issue in the DOM: Copy & Paste and Drag & Drop component

CVE-2026-0891: Memory safety bugs fixed in Firefox ESR 140.7, Thunderbird ESR 140.7, Firefox 147 and Thunderbird 147

Memory safety bugs present in Firefox ESR 140.6, Thunderbird ESR 140.6, Firefox 146 and Thunderbird 146. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2026-0892: Memory safety bugs fixed in Firefox 147 and Thunderbird 147

Memory safety bugs present in Firefox 146 and Thunderbird 146. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Mozilla Firefox versions prior to 147.");

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

if (version_is_less(version: version, test_version: "147")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "147", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);