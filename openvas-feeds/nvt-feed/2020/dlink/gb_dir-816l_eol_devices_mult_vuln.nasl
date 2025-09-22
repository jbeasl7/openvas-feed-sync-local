# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dir-816l_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144346");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2020-08-04 02:12:24 +0000 (Tue, 04 Aug 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-24 20:08:00 +0000 (Fri, 24 Jul 2020)");

  # nb: Unlike other VTs we're using the CVEs line by line here for easier addition of new CVEs / to
  #     avoid too large diffs when adding a new CVE.
  script_cve_id("CVE-2020-15893",
                "CVE-2020-15894",
                "CVE-2020-15895",
                "CVE-2025-7836",
                "CVE-2025-9727"
                );

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("D-Link DIR-816L Devices Multiple Vulnerabilities (2020 - 2025)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"D-Link DIR-816L is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a vulnerable device.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-15893: Command injection in the UPnP via a crafted M-SEARCH packet

  - CVE-2020-15894: Exposed administration function, allowing unauthorized access to the few
  sensitive information

  - CVE-2020-15895: Reflected XSS due to an unescaped value on the device configuration webpage

  - CVE-2025-7836: Command injection in the function lxmldbc_system of the file /htdocs/cgibin

  - CVE-2025-9727: Command injection in the function soapcgi_main of the file /soap.cgi.");

  script_tag(name:"affected", value:"D-Link DIR-816L devices in all versions.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: Vendor states that DIR-816L reached its End-of-Support Date in 01.03.2016, it is no longer
  supported, and firmware development has ceased. See vendor advisory for further
  recommendations.");

  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10169");
  script_xref(name:"URL", value:"https://research.loginsoft.com/vulnerability/multiple-vulnerabilities-discovered-in-the-d-link-firmware-dir-816l/");
  script_xref(name:"URL", value:"https://github.com/bananashipsBBQ/CVE/blob/main/D-Link%20DIR-816L%20Remote%20Arbitrary%20Command%20Execution%20Vulnerability%20in%20ssdpcgi.md");
  script_xref(name:"URL", value:"https://service.dlink.co.in/resources/EOL-Products-Without-Service.pdf");
  script_xref(name:"URL", value:"https://legacy.us.dlink.com/");
  script_xref(name:"URL", value:"https://github.com/scanleale/IOT_sec/blob/main/DIR-816L.pdf");
  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10300");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

report = report_fixed_ver(installed_version: version, fixed_version: "None");
security_message(port: 0, data: report);
exit(0);
