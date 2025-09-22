# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.883072");
  script_version("2025-01-21T05:37:33+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2019-11703", "CVE-2019-11704", "CVE-2019-11705", "CVE-2019-11706", "CVE-2019-11707", "CVE-2019-11708");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-02 17:02:19 +0000 (Tue, 02 Jul 2024)");
  script_tag(name:"creation_date", value:"2019-07-02 02:00:30 +0000 (Tue, 02 Jul 2019)");
  script_name("CentOS Update for thunderbird CESA-2019:1624 centos6");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");

  script_xref(name:"CESA", value:"2019:1624");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-July/023347.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the CESA-2019:1624 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail and newsgroup client.

This update upgrades Thunderbird to version 60.7.2.

Security Fix(es):

  * Mozilla: Type confusion in Array.pop (CVE-2019-11707)

  * thunderbird: Stack buffer overflow in icalrecur_add_bydayrules in
icalrecur.c (CVE-2019-11705)

  * Mozilla: Sandbox escape using Prompt:Open (CVE-2019-11708)

  * thunderbird: Heap buffer over read in icalparser.c parser_get_next_char
(CVE-2019-11703)

  * thunderbird: Heap buffer overflow in icalmemory_strdup_and_dequote
function in icalvalue.c (CVE-2019-11704)

  * thunderbird: Type confusion in icaltimezone_get_vtimezone_properties
function in icalproperty.c (CVE-2019-11706)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'thunderbird' package(s) on CentOS 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "CentOS6") {

  if(!isnull(res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~60.7.2~2.el6.centos", rls:"CentOS6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
