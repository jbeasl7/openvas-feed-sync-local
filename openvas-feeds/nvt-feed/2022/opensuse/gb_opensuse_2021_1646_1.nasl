# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.854451");
  script_version("2025-02-28T05:38:49+0000");
  script_cve_id("CVE-2021-44540", "CVE-2021-44541", "CVE-2021-44542", "CVE-2021-44543");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-06 16:15:00 +0000 (Thu, 06 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-02-08 08:16:18 +0000 (Tue, 08 Feb 2022)");
  script_name("openSUSE: Security Advisory for privoxy (openSUSE-SU-2021:1646-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1646-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QYO5MMUZFNF4G2ZDKAE76JYKJCV2JPWK");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'privoxy'
  package(s) announced via the openSUSE-SU-2021:1646-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for privoxy fixes the following issues:
  privoxy was updated to 3.0.33 (boo#1193584):

  * CVE-2021-44543: Encode the template name to prevent XSS (cross-site
  scripting) when Privoxy is configured to service the user-manual itself

  * CVE-2021-44540: Free memory of compiled pattern spec before bailing

  * CVE-2021-44541: Free header memory when failing to get the request
  destination.

  * CVE-2021-44542: Prevent memory leaks when handling errors

  * Disable fast-redirects for a number of domains

  * Update default block lists

  * Many bug fixes and minor enhancements");

  script_tag(name:"affected", value:"'privoxy' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"privoxy", rpm:"privoxy~3.0.33~lp152.3.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"privoxy-debuginfo", rpm:"privoxy-debuginfo~3.0.33~lp152.3.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"privoxy-debugsource", rpm:"privoxy-debugsource~3.0.33~lp152.3.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"privoxy-doc", rpm:"privoxy-doc~3.0.33~lp152.3.12.1", rls:"openSUSELeap15.2"))) {
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
