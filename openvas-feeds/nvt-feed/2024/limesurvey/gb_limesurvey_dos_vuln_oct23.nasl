# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:limesurvey:limesurvey";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152904");
  script_version("2024-08-21T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-08-21 05:05:38 +0000 (Wed, 21 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-08-20 01:58:42 +0000 (Tue, 20 Aug 2024)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:N/I:N/A:P");

  script_cve_id("CVE-2024-7887");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("LimeSurvey < 6.3.0 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_limesurvey_detect.nasl");
  script_mandatory_keys("limesurvey/http/detected");

  script_tag(name:"summary", value:"LimeSurvey is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is associated with surveys published by
  administrators that include the 'file upload' option. During the survey submission process, users
  can upload files, and the system validates the size of uploaded files. However, proper input
  validation is not performed on the uploaded file size, enabling attackers to manipulate submitted
  data to bypass the expected handling of the system.

  Specifically, attackers can manipulate the submitted data and set the 'size' parameter to a
  non-integer value, such as a string. Due to the lack of appropriate input validation, the system
  fails to handle this non-integer value correctly, resulting in an error. This error renders
  administrators unable to access statistical results for the affected survey, as the system fails
  to correctly parse the input data.");

  script_tag(name:"affected", value:"LimeSurvey prior to version 6.3.0.");

  script_tag(name:"solution", value:"Update to version 6.3.0 or later.");

  script_xref(name:"URL", value:"https://huntr.com/bounties/6636038f-5cc7-4f87-8a50-922d139d6485");
  script_xref(name:"URL", value:"https://github.com/limesurvey/limesurvey/commit/b1146f3f31437c3b4891a74418041dc1441b76d8");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "6.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.3.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
