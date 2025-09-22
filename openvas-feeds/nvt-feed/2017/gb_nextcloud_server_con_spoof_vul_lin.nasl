# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107145");
  script_version("2025-02-25T13:24:30+0000");
  script_tag(name:"last_modification", value:"2025-02-25 13:24:30 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"creation_date", value:"2017-04-10 09:39:06 +0200 (Mon, 10 Apr 2017)");
  script_cve_id("CVE-2017-0883", "CVE-2017-0884", "CVE-2017-0885", "CVE-2017-0886",
                "CVE-2017-0887", "CVE-2017-0888");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-04 14:20:00 +0000 (Tue, 04 Oct 2022)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Nextcloud Server Multiple Vulnerabilities - Linux");
  script_tag(name:"summary", value:"Nextcloud Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - the top navigation bar displayed in the files list contained partially
    user-controllable input leading to a potential misrepresentation of information.

  - an error in the application logic an authenticated adversary may trigger
    an endless recursion in the application.

  - not properly sanitizing values provided by the `OC-Total-Length` HTTP
    header an authenticated adversary may be able to exceed their configured user
    quota.

  - an error in the application logic an adversary with access to a
    write-only share may enumerate the names of existing files and subfolders by
    comparing the exception messages.

  - a permission related issue within the OCS sharing API allowed an authenticated
    adversary to reshare shared files with an increasing permission set.

  - a logical error in the file caching layer an authenticated adversary is
    able to create empty folders inside a shared folder.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to edit files in a share, lead to a potential misrepresentation of information,
  and can cause denial of service conditions.");

  script_tag(name:"affected", value:"Versions prior to Nextcloud Server 9.0.55
  and 10.0.2 are vulnerable");
  script_tag(name:"solution", value:"Updates are available. Please see the
  references or vendor advisory for more information.");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97491");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");

  script_family("Web application abuses");

  script_dependencies("gb_nextcloud_server_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("nextcloud/server/detected", "Host/runs_unixoide");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!Port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!Ver = get_app_version(cpe:CPE, port:Port)){
  exit(0);
}

if(Ver =~ "^9\.0\."){
  if(version_is_less(version:Ver, test_version:"9.0.55")){
    Vuln = TRUE;
    fix = "9.0.55";
  }
}
else if(Ver =~ "^10\.0\."){
  if(version_is_less(version:Ver, test_version:"10.0.2")){
    Vuln = TRUE;
    fix = "10.0.2";
  }
}

if(Vuln){
  report = report_fixed_ver(installed_version:Ver, fixed_version:fix);
  security_message(port:Port, data:report);
  exit(0);
}

exit(99);
