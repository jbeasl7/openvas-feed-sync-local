# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.852477");
  script_version("2025-08-07T05:44:51+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2019-5418", "CVE-2019-5419");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-08-07 05:44:51 +0000 (Thu, 07 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-16 19:02:00 +0000 (Fri, 16 Oct 2020)");
  script_tag(name:"creation_date", value:"2019-05-09 02:00:44 +0000 (Thu, 09 May 2019)");
  script_name("openSUSE: Security Advisory for rubygem-actionpack-5_1 (openSUSE-SU-2019:1344-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2019:1344-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-05/msg00011.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rubygem-actionpack-5_1'
  package(s) announced via the openSUSE-SU-2019:1344-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rubygem-actionpack-5_1 fixes the following issues:

  Security issues fixed:

  - CVE-2019-5418: Fixed a file content disclosure vulnerability in Action
  View which could be exploited via specially crafted accept headers in
  combination with calls to render file (bsc#1129272).

  - CVE-2019-5419: Fixed a resource exhaustion issue in Action View which
  could make the server unable to process requests (bsc#1129271).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1344=1");

  script_tag(name:"affected", value:"'rubygem-actionpack-5_1' package(s) on openSUSE Leap 15.0.");

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

if(release == "openSUSELeap15.0") {

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-actionpack-5_1", rpm:"ruby2.5-rubygem-actionpack-5_1~5.1.4~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uby2.5-rubygem-actionpack-doc-5_1", rpm:"uby2.5-rubygem-actionpack-doc-5_1~5.1.4~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
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
