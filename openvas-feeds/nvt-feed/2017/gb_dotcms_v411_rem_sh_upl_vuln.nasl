# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dotcms:dotcms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112089");
  script_version("2024-07-26T15:38:40+0000");
  script_tag(name:"last_modification", value:"2024-07-26 15:38:40 +0000 (Fri, 26 Jul 2024)");
  script_tag(name:"creation_date", value:"2017-10-20 11:29:18 +0200 (Fri, 20 Oct 2017)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-25 14:59:00 +0000 (Tue, 25 Jul 2017)");

  script_cve_id("CVE-2017-11466");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("dotCMS 4.1.1 Remote Shell Upload Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dotcms_http_detect.nasl");
  script_mandatory_keys("dotcms/detected");

  script_tag(name:"summary", value:"dotCMS is prone to a remote shell upload vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Arbitrary file upload vulnerability in
  com/dotmarketing/servlets/AjaxFileUploadServlet.class allows remote authenticated administrators
  to upload .jsp files to arbitrary locations via directory traversal sequences in the fieldName
  parameter to servlets/ajax_file_upload.");

  script_tag(name:"impact", value:"Remotely authenticated attackers might use this vulnerability to
  execute arbitrary code on the target.");

  script_tag(name:"affected", value:"dotCMS version 4.1.1.");

  script_tag(name:"solution", value:"Update to version 4.2.0 or later.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Jul/33");
  script_xref(name:"URL", value:"https://github.com/dotCMS/core/issues/12131");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/143383/dotcms411-shell.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: version, test_version: "4.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
