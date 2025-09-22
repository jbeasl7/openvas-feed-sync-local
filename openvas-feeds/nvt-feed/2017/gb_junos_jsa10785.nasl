# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:juniper:junos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106748");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-04-13 08:24:49 +0200 (Thu, 13 Apr 2017)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");

  script_cve_id("CVE-2016-2776", "CVE-2016-8864", "CVE-2016-9131", "CVE-2016-9147", "CVE-2016-9444");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Juniper Networks Junos OS Multiple BIND Vulnerabilities (JSA10785)");

  script_category(ACT_GATHER_INFO);

  script_family("JunOS Local Security Checks");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_juniper_junos_consolidation.nasl");
  script_mandatory_keys("juniper/junos/detected");

  script_tag(name:"summary", value:"Junos OS is prone to multiple denial of service vulnerabilities in ISC
  BIND named.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were found in the BIND version used by Junos OS:

  - buffer.c in named in ISC BIND does not properly construct responses, which allows remote attackers to cause a
  denial of service via a crafted query. (CVE-2016-2776)

  - named in ISC BIND allows remote attackers to cause a denial of service via a DNAME record in the answer section
  of a response to a recursive query, related to db.c and resolver.c. (CVE-2016-8864)

  - named in ISC BIND allows remote attackers to cause a denial of service via a malformed response to an RTYPE ANY
  query. (CVE-2016-9131)

  - named in ISC BIND allows remote attackers to cause a denial of service via a response containing an
  inconsistency among the DNSSEC-related RRsets. (CVE-2016-9147)

  - named in ISC BIND allows remote attackers to cause a denial of service via a crafted DS resource record in an
  answer. (CVE-2016-9444)");

  script_tag(name:"impact", value:"An attacker may cause a denial of service condition.");

  script_tag(name:"affected", value:"Junos OS 12.1X46, 12.3X48 and 15.1X49.");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper. As a
  workaround disable the DNS proxy service.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10785");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if ((revcomp(a: version, b: "12.1X46-D66") < 0) &&
    (revcomp(a: version, b: "12.1X46") >= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.1X46-D66");
  security_message(port: 0, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "12.3X48-D50") < 0) &&
    (revcomp(a: version, b: "12.3X48") >= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.3X48-D50");
  security_message(port: 0, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "15.1X49-D80") < 0) &&
    (revcomp(a: version, b: "15.1X49") >= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.1X49-D80");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
