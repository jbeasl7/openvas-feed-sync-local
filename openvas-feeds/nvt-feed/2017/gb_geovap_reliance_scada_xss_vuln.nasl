# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:geovap:reliance-scada";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112150");
  script_version("2025-03-20T05:38:32+0000");
  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"creation_date", value:"2017-12-07 08:23:03 +0100 (Thu, 07 Dec 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:25:00 +0000 (Wed, 09 Oct 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-16721");

  script_name("Geovap Reliance SCADA XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_geovap_reliance_scada_detect.nasl");
  script_mandatory_keys("geovap/reliance-scada/detected", "geovap/reliance-scada/version");

  script_tag(name:"summary", value:"Geovap Reliance SCADA is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"impact", value:"Successful exploitation of this vulnerability could allow an unauthenticated attacker
to inject arbitrary JavaScript in a specially crafted URL request that may allow for read/write access.");
  script_tag(name:"affected", value:"Reliance SCADA Version 4.7.3 Update 2 and prior.");
  script_tag(name:"solution", value:"Geovap has released Version 4.7.3 Update 3");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-17-334-02");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102031");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

# nb: This returns an unexpected version so the other one below is used instead
if (!get_app_version(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

if (!version = get_kb_item("geovap/reliance-scada/version"))
  exit(0);

if (version_is_less(version: version, test_version: "4.7.3 Update 3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.7.3 Update 3");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
