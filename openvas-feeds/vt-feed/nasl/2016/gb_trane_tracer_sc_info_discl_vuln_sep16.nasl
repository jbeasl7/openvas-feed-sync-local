# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:trane:tracer_sc_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106273");
  script_version("2026-03-25T05:58:02+0000");
  script_tag(name:"last_modification", value:"2026-03-25 05:58:02 +0000 (Wed, 25 Mar 2026)");
  script_tag(name:"creation_date", value:"2016-09-20 17:00:53 +0700 (Tue, 20 Sep 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 19:55:00 +0000 (Mon, 28 Nov 2016)");

  script_cve_id("CVE-2016-0870");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Trane Tracer SC <= 4.2.1134 Information Exposure Vulnerability - Version Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_trane_tracer_sc_consolidation.nasl");
  script_mandatory_keys("trane/tracer/detected");

  script_tag(name:"summary", value:"Trane Tracer SC is prone to an information exposure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability allows an unauthorized party to obtain
  sensitive information from the contents of configuration files not protected by the web
  server.");

  script_tag(name:"impact", value:"An unauthorized attacker can exploit this vulnerability to read
  sensitive information from the contents of configuration files.");

  script_tag(name:"affected", value:"Trane Tracer SC version 4.2.1134 and prior.");

  script_tag(name:"solution", value:"Contact the vendor for an update.");

  script_xref(name:"URL", value:"https://www.cisa.gov/news-events/ics-advisories/icsa-16-259-03");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "4.2.1134")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Contact vendor");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
