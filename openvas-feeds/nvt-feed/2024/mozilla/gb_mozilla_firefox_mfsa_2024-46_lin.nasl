# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2024.46");
  script_cve_id("CVE-2024-9392", "CVE-2024-9393", "CVE-2024-9394", "CVE-2024-9396", "CVE-2024-9397", "CVE-2024-9398", "CVE-2024-9399", "CVE-2024-9400", "CVE-2024-9401", "CVE-2024-9402", "CVE-2024-9403");
  script_tag(name:"creation_date", value:"2024-10-02 07:13:00 +0000 (Wed, 02 Oct 2024)");
  script_version("2024-10-16T08:00:45+0000");
  script_tag(name:"last_modification", value:"2024-10-16 08:00:45 +0000 (Wed, 16 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-15 16:04:59 +0000 (Tue, 15 Oct 2024)");

  script_name("Mozilla Firefox Security Advisory (MFSA2024-46) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2024-46");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-46/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1872744%2C1897792%2C1911317%2C1913445%2C1914106%2C1914475%2C1914963%2C1915008%2C1916476");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1872744%2C1897792%2C1911317%2C1916476");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1881037");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1899154");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1905843");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1907726");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1912471");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1915249");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1916659");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1917807");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1918301");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1918874");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2024-9392: Compromised content process can bypass site isolation
A compromised content process could have allowed for the arbitrary loading of cross-origin pages.

CVE-2024-9393: Cross-origin access to PDF contents through multipart responses
An attacker could, via a specially crafted multipart response, execute arbitrary JavaScript under the resource://pdf.js origin. This could allow them to access cross-origin PDF content. This access is limited to 'same site' documents by the Site Isolation feature on desktop clients, but full cross-origin access is possible on Android versions.

CVE-2024-9394: Cross-origin access to JSON contents through multipart responses
An attacker could, via a specially crafted multipart response, execute arbitrary JavaScript under the resource://devtools origin. This could allow them to access cross-origin JSON content. This access is limited to 'same site' documents by the Site Isolation feature on desktop clients, but full cross-origin access is possible on Android versions.

CVE-2024-9396: Potential memory corruption may occur when cloning certain objects
It is currently unknown if this issue is exploitable but a condition may arise where the structured clone of certain objects could lead to memory corruption.

CVE-2024-9397: Potential directory upload bypass via clickjacking
A missing delay in directory upload UI could have made it possible for an attacker to trick a user into granting permission via clickjacking.

CVE-2024-9398: External protocol handlers could be enumerated via popups
By checking the result of calls to window.open with specifically set protocol handlers, an attacker could determine if the application which implements that protocol handler is installed.

CVE-2024-9399: Specially crafted WebTransport requests could lead to denial of service
A website configured to initiate a specially crafted WebTransport session could crash the Firefox process leading to a denial of service condition.

CVE-2024-9400: Potential memory corruption during JIT compilation
A potential memory corruption vulnerability could be triggered if an attacker had the ability to trigger an OOM at a specific moment during JIT compilation.

CVE-2024-9401: Memory safety bugs ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 131.");

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

if (version_is_less(version: version, test_version: "131")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "131", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
