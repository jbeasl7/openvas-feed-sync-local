# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:portainer:portainer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114162");
  script_version("2024-11-05T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-11-05 05:05:33 +0000 (Tue, 05 Nov 2024)");
  script_tag(name:"creation_date", value:"2019-11-08 16:14:12 +0100 (Fri, 08 Nov 2019)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_cve_id("CVE-2019-16872", "CVE-2019-16873", "CVE-2019-16874", "CVE-2019-16876",
                "CVE-2019-16877", "CVE-2019-16878");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Portainer < 1.22.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_portainer_http_detect.nasl");
  script_mandatory_keys("portainer/detected");

  script_tag(name:"summary", value:"Portainer is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Portainer is prone to multiple vulnerabilities:

  - CVE-2019-16872: An Unrestricted Host Filesystem Access vulnerability exists in Stack creation
  feature in Portainer. Successful exploitation of this vulnerability would allow an authenticated
  user to gain full permission on the host filesystem.

  - CVE-2019-16873: A Stored Cross-Site Scripting vulnerability exists in the isteven-multi-select
  component in Portainer. Successful exploitation of this vulnerability would allow authenticated
  users to inject arbitrary Javascript into Portainer pages viewed by other users.

  - CVE-2019-16874: An Improper Access Control vulnerability exists in the RBAC extension in
  Portainer. Successful exploitation of this vulnerability would allow Helpdesk users to access
  sensitive information via the volume browsing feature.

  - CVE-2019-16876: A path traversal vulnerability exists in Portainer. Successful exploitation of
  this vulnerability would allow an authenticated user to upload files to an arbitrary location.

  - CVE-2019-16877: An authorization bypass vulnerability exists in Portainer. Successful
  exploitation of this vulnerability would allow an authenticated user to gain full permission on a
  host filesystem via the Host Management API.

  - CVE-2019-16878: A Stored Cross-Site Scripting vulnerability exists in the file removal
  confirmation modal in Portainer. Successful exploitation of this vulnerability would allow an
  authenticated user to inject arbitrary Javascript into Portainer pages viewed by other users.");

  script_tag(name:"affected", value:"Portainer versions before 1.22.1.");

  script_tag(name:"solution", value:"Update to Portainer 1.22.1 or later.");


  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if(version_is_less(version: version, test_version: "1.22.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.22.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
