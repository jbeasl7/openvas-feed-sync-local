# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:elasticsearch";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814075");
  script_version("2025-09-03T08:26:15+0000");
  script_cve_id("CVE-2018-3826");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-03 08:26:15 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:40:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-10-09 11:12:08 +0530 (Tue, 09 Oct 2018)");
  script_name("Elasticsearch '_snapshot API' Information Disclosure Vulnerability - Windows");

  script_tag(name:"summary", value:"Elasticsearch is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error when access_key
  and security_key parameters are set via the '_snapshot' API.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to query the _snapshot API and leak sensitive information.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"affected", value:"Elasticsearch versions 6.0.0-beta1 to 6.2.4.");

  script_tag(name:"solution", value:"Update to Elasticsearch version 6.3.0 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elastic-stack-6-3-0-and-5-6-10-security-update/135777");
  script_xref(name:"URL", value:"https://www.elastic.co/community/security");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_elastic_elasticsearch_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("elastic/elasticsearch/detected", "Host/runs_windows");

  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe: CPE)))
 exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(revcomp(a:vers, b:"6.0.0-beta1") >= 0 && revcomp(a:vers, b:"6.2.4") <= 0) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"6.3.0", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);