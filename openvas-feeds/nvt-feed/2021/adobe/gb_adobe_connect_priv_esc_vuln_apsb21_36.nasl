# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:connect";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818157");
  script_version("2023-09-15T16:10:33+0000");
  script_tag(name:"last_modification", value:"2023-09-15 16:10:33 +0000 (Fri, 15 Sep 2023)");
  script_tag(name:"creation_date", value:"2021-06-10 11:53:47 +0530 (Thu, 10 Jun 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-02 14:31:00 +0000 (Fri, 02 Jul 2021)");

  script_cve_id("CVE-2021-28579");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Adobe Connect Privilege Escalation Vulnerability (APSB21-36)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_adobe_connect_http_detect.nasl");
  script_mandatory_keys("adobe/connect/detected");

  script_tag(name:"summary", value:"Adobe Connect is prone to a privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper access control error in Adobe
  Connect software.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct
  privilege escalation.");

  script_tag(name:"affected", value:"Adobe Connect version 11.2.1 and prior.");

  script_tag(name:"solution", value:"Update to version 11.2.2 or later.");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/connect/apsb21-36.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "11.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.2.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
