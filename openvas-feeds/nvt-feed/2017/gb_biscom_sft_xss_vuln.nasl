# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:biscom:secure_file_transfer";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140301");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-08-15 16:54:53 +0700 (Tue, 15 Aug 2017)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-20 22:15:00 +0000 (Thu, 20 Feb 2020)");

  script_cve_id("CVE-2017-5241");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Biscom Secure File Transfer XSS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_biscom_sft_detect.nasl");
  script_mandatory_keys("biscom_sft/installed");

  script_tag(name:"summary", value:"Biscom Secure File Transfer is prone to a cross-site scripting
vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Workspaces component of Biscom Secure File Transfer (SFT) is vulnerable
to stored cross-site scripting in two fields. An attacker would need to have the ability to create a Workspace
and entice a victim to visit the malicious page in order to run malicious Javascript in the context of the
victim's browser. Since the victim is necessarily authenticated, this can allow the attacker to perform actions
on the Biscom Secure File Transfer instance on the victim's behalf.");

  script_tag(name:"affected", value:"Synology Photo Station before 5.1.1025.");

  script_tag(name:"solution", value:"Update to version 5.1.1025 or later.");

  script_xref(name:"URL", value:"https://community.rapid7.com/community/infosec/blog/2017/06/27/r7-2017-06-biscom-sftp-xss-cve-2017-5241");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "5.1.1025")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.1025");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
