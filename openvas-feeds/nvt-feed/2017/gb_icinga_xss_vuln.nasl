# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:icinga:icinga";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106710");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-03-31 09:02:03 +0700 (Fri, 31 Mar 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_cve_id("CVE-2015-8010");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Icinga XSS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_icinga_detect.nasl");
  script_mandatory_keys("icinga/installed");

  script_tag(name:"summary", value:"Icinga is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Cross-site scripting vulnerability in the Classic-UI with the CSV export
link and pagination feature allows remote attackers to inject arbitrary web script or HTML via the query string
to cgi-bin/status.cgi.");

  script_tag(name:"affected", value:"Icinga prior to 1.14.0.");

  script_tag(name:"solution", value:"Update 1.14.0 or later versions.");

  script_xref(name:"URL", value:"https://github.com/Icinga/icinga-core/issues/1563");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.14.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.14.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
