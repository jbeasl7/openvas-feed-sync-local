# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807396");
  script_version("2023-11-17T16:10:13+0000");
  script_tag(name:"last_modification", value:"2023-11-17 16:10:13 +0000 (Fri, 17 Nov 2023)");
  script_tag(name:"creation_date", value:"2017-02-08 11:32:12 +0530 (Wed, 08 Feb 2017)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-03 16:12:00 +0000 (Fri, 03 Feb 2017)");

  script_cve_id("CVE-2016-9260");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus < 6.9 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_tenable_nessus_consolidation.nasl");
  script_mandatory_keys("tenable/nessus/detected");

  script_tag(name:"summary", value:"Tenable Nessus is prone to a stored cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in handling of '.nessus' files, which
  allows attackers to execute arbitrary HTML and script code in the context of an affected application
  or site.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject
  arbitrary web script or HTML.");

  script_tag(name:"affected", value:"Tenable Nessus prior to version 6.9.");

  script_tag(name:"solution", value:"Update to version 6.9 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2016-16");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95772");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2017/JVNDB-2017-000013.html");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN12796388/index.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
location = infos["location"];

if(version_is_less(version:vers, test_version:"6.9")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"6.9", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
