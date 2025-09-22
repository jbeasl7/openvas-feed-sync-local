# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dotcms:dotcms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106572");
  script_version("2024-07-26T15:38:40+0000");
  script_tag(name:"last_modification", value:"2024-07-26 15:38:40 +0000 (Fri, 26 Jul 2024)");
  script_tag(name:"creation_date", value:"2017-02-07 11:43:11 +0700 (Tue, 07 Feb 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-15 19:55:00 +0000 (Fri, 15 Mar 2019)");

  script_cve_id("CVE-2017-5876", "CVE-2017-5875", "CVE-2017-5877", "CVE-2017-6003");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("dotCMS <= 3.7.0 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dotcms_http_detect.nasl");
  script_mandatory_keys("dotcms/detected");

  script_tag(name:"summary", value:"dotCMS is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2017-5875: XSS with an authenticated attack against the /myAccount addressID parameter

  - CVE-2017-5876: XSS with an unauthenticated attack against the /news-events/events date
  parameter

  - CVE-2017-5877: XSS with an unauthenticated attack against the /about-us/locations/index
  direction parameter");

  script_tag(name:"affected", value:"dotCMS version 3.7.0 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"https://github.com/dotCMS/core/issues/10643");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "3.7.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
