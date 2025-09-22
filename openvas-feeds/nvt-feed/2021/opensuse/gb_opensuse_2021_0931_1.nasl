# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.853892");
  script_version("2025-02-28T05:38:49+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-18670", "CVE-2020-18671", "CVE-2020-35730");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-13 04:15:00 +0000 (Wed, 13 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-06-28 03:01:11 +0000 (Mon, 28 Jun 2021)");
  script_name("openSUSE: Security Advisory for roundcubemail (openSUSE-SU-2021:0931-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0931-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/BPPHYZD6Y3QJBTGPLX66Y3DJ3KCNEUJQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'roundcubemail'
  package(s) announced via the openSUSE-SU-2021:0931-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for roundcubemail fixes the following issues:

     Upgrade to version 1.3.16

     This is a security update to the LTS version 1.3.

     It fixes a recently reported stored cross-site scripting (XSS)
     vulnerability via HTML or plain text messages with malicious content.

     References:

  - CVE-2020-18670: Cross Site Scripting (XSS) vulneraibility via database
       host and user in /installer/test.php (boo#1187707)

  - CVE-2020-18671: Cross Site Scripting (XSS) vulnerability via smtp config
       in /installer/test.php (boo#1187706)

  - CVE-2020-35730: cross-site scripting (XSS) vulnerability via HTML or
       plain text messages with malicious content (boo#1180399)");

  script_tag(name:"affected", value:"'roundcubemail' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"roundcubemail", rpm:"roundcubemail~1.3.16~lp152.4.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);