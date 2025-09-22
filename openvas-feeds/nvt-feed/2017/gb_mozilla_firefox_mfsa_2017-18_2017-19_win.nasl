# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811571");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2017-7798", "CVE-2017-7800", "CVE-2017-7801", "CVE-2017-7809",
                "CVE-2017-7784", "CVE-2017-7802", "CVE-2017-7785", "CVE-2017-7786",
                "CVE-2017-7806", "CVE-2017-7753", "CVE-2017-7787", "CVE-2017-7807",
                "CVE-2017-7792", "CVE-2017-7804", "CVE-2017-7791", "CVE-2017-7808",
                "CVE-2017-7782", "CVE-2017-7781", "CVE-2017-7803", "CVE-2017-7779",
                "CVE-2017-7799", "CVE-2017-7783", "CVE-2017-7788", "CVE-2017-7789",
                "CVE-2017-7790", "CVE-2017-7796", "CVE-2017-7797", "CVE-2017-7780");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-01 12:04:00 +0000 (Wed, 01 Aug 2018)");
  script_tag(name:"creation_date", value:"2017-08-10 11:40:27 +0530 (Thu, 10 Aug 2017)");
  script_name("Mozilla Firefox Security Advisories (MFSA2017-18, MFSA2017-19) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - XUL injection in the style editor in devtools.

  - Use-after-free in WebSockets during disconnection.

  - Use-after-free with marquee during window resizing.

  - Use-after-free while deleting attached editor DOM node.

  - Use-after-free with image observers.

  - Use-after-free resizing image elements.

  - Buffer overflow manipulating ARIA attributes in DOM.

  - Buffer overflow while painting non-displayable SVG.

  - Use-after-free in layer manager with SVG.

  - Out-of-bounds read with cached style data and pseudo-elements.

  - Same-origin policy bypass with iframes through page reloads.

  - Domain hijacking through AppCache fallback.

  - Buffer overflow viewing certificates with an extremely long OID.

  - Memory protection bypass through WindowsDllDetourPatcher.

  - Spoofing following page navigation with data: protocol and modal alerts.

  - CSP information leak with frame-ancestors containing paths.

  - WindowsDllDetourPatcher allocates memory without DEP protections.

  - Elliptic curve point addition error when using mixed Jacobian-affine coordinates.

  - CSP containing sandbox is improperly applied.

  - Self-XSS XUL injection in about:webrtc.

  - DOS attack through long username in URL.

  - Sandboxed about:srcdoc iframes do not inherit CSP directives.

  - Failure to enable HSTS when two STS headers are sent for a connection.

  - Windows crash reporter reads extra memory for some non-null-terminated registry values.

  - Windows updater can delete any file named update.log.

  - Response header name interning leaks across origins.

  - Memory safety bugs fixed in Firefox 55.

  - Memory safety bugs fixed in Firefox 55 and Firefox ESR 52.3.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow remote attackers to run arbitrary code, obtain
  sensitive information, cause denial of service, conduct cross-site scripting (XSS)
  attack, spoofing attack and bypass existing memory protections.");

  script_tag(name:"affected", value:"Mozilla Firefox versions before 55.0.");

  script_tag(name:"solution", value:"Update to version 55.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-18/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"55.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"55.0", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
