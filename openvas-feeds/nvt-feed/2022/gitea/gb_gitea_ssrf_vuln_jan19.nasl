# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gitea:gitea";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124003");
  script_version("2024-06-27T05:05:29+0000");
  script_tag(name:"last_modification", value:"2024-06-27 05:05:29 +0000 (Thu, 27 Jun 2024)");
  script_tag(name:"creation_date", value:"2022-02-11 12:04:03 +0000 (Fri, 11 Feb 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-11 17:07:00 +0000 (Fri, 11 Feb 2022)");

  script_cve_id("CVE-2021-45325");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Gitea < 1.7.0 SSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_gitea_http_detect.nasl");
  script_mandatory_keys("gitea/detected");

  script_tag(name:"summary", value:"Gitea is prone to a server-side request forgery (SSRF)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A SSRF vulnerability exists in Gitea when using the OpenID
  URL.");

  script_tag(name:"affected", value:"Gitea prior to version 1.7.0.");

  script_tag(name:"solution", value:"Update to version 1.7.0 or later.");

  script_xref(name:"URL", value:"https://github.com/go-gitea/gitea/releases/tag/v1.7.0");
  script_xref(name:"URL", value:"https://blog.gitea.io/2019/01/gitea-1.7.0-is-released/");

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

if (version_is_less(version: version, test_version: "1.7.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.7.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
