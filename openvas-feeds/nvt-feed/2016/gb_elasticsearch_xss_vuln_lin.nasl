# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:elasticsearch";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808506");
  script_version("2025-09-03T08:26:15+0000");
  script_cve_id("CVE-2014-6439");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-09-03 08:26:15 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-06-28 18:37:05 +0530 (Tue, 28 Jun 2016)");
  script_name("Elasticsearch Cross-site Scripting (XSS) Vulnerability - Linux");

  script_tag(name:"summary", value:"Elasticsearch is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Flaw is due to an error in the
  CORS functionality.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"affected", value:"Elasticsearch version 1.3.x and prior
  on Linux.");

  script_tag(name:"solution", value:"Update to Elasticsearch version 1.4.0.Beta1,
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.elastic.co/community/security/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70233");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/533602/100/0/threaded");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_elastic_elasticsearch_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("elastic/elasticsearch/detected", "Host/runs_unixoide");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(esPort = get_app_port(cpe:CPE))){
 exit(0);
}

if(!esVer = get_app_version(cpe:CPE, port:esPort)){
 exit(0);
}

esVer1 = eregmatch(pattern:"([0-9.]+)", string:esVer);
esVer = esVer1[1];

##version info taken from https://www.elastic.co/downloads/past-releases
if(version_is_less(version:esVer, test_version:"1.4.0"))
{
  report = report_fixed_ver(installed_version:esVer, fixed_version:"1.4.0.Beta1");
  security_message(data:report, port:esPort);
  exit(0);
}

