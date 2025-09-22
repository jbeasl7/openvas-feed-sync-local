# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2025.14");
  script_cve_id("CVE-2025-1931", "CVE-2025-1932", "CVE-2025-1933", "CVE-2025-1934", "CVE-2025-1935", "CVE-2025-1936", "CVE-2025-1937", "CVE-2025-1938", "CVE-2025-1942", "CVE-2025-1943");
  script_tag(name:"creation_date", value:"2025-03-05 08:23:50 +0000 (Wed, 05 Mar 2025)");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mozilla Firefox Security Advisory (MFSA2025-14) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2025-14");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-14/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1869650%2C1938451%2C1940326%2C1944052%2C1944063%2C1947281");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1922889%2C1935004%2C1943586%2C1943912%2C1948111");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1938471%2C1940716");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1866661");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1940027");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1942881");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1944126");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1944313");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1946004");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1947139");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2025-1931: Use-after-free in WebTransportChild
It was possible to cause a use-after-free in the content process side of a WebTransport connection, leading to a potentially exploitable crash.

CVE-2025-1932: Inconsistent comparator in XSLT sorting led to out-of-bounds access
An inconsistent comparator in xslt/txNodeSorter could have resulted in potentially exploitable out-of-bounds access. Only affected version 122 and later.

CVE-2025-1933: JIT corruption of WASM i32 return values on 64-bit CPUs
On 64-bit CPUs, when the JIT compiles WASM i32 return values they can pick up bits from left over memory. This can potentially cause them to be treated as a different type.

CVE-2025-1934: Unexpected GC during RegExp bailout processing
It was possible to interrupt the processing of a RegExp bailout and run additional JavaScript, potentially triggering garbage collection when the engine was not expecting it.

CVE-2025-1942: Disclosure of uninitialized memory when .toUpperCase() causes string to get longer
When String.toUpperCase() caused a string to get longer it was possible for uninitialized memory to be incorporated into the result string

CVE-2025-1935: Clickjacking the registerProtocolHandler info-bar
A web page could trick a user into setting that site as the default handler for a custom URL protocol.

CVE-2025-1936: Adding %00 and a fake extension to a jar: URL changed the interpretation of the contents
jar: URLs retrieve local file ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 136.");

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

if (version_is_less(version: version, test_version: "136")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "136", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
