# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dokuwiki:dokuwiki";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112025");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"creation_date", value:"2017-08-22 10:27:42 +0200 (Tue, 22 Aug 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-25 16:52:00 +0000 (Fri, 25 Aug 2017)");

  script_cve_id("CVE-2017-12979", "CVE-2017-12980");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("DokuWiki <= 2017-02-19c Stored XSS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dokuwiki_detect.nasl");
  script_mandatory_keys("dokuwiki/installed");

  script_tag(name:"summary", value:"DokuWiki has stored XSS when rendering a malicious RSS or Atom feed or language name in a code element, in /inc/parser/xhtml.php. An attacker can create or edit a wiki with this element to trigger   JavaScript execution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"DokuWiki version 2017-02-19c and prior.");

  script_tag(name:"solution", value:"Upgrade to pull request #2083 and/or #2086 respectively to fix the issues.");

  script_xref(name:"URL", value:"https://github.com/splitbrain/dokuwiki/issues/2080");
  script_xref(name:"URL", value:"https://github.com/splitbrain/dokuwiki/issues/2081");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "2017-02-19c")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See references");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
