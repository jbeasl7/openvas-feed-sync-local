# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856045");
  script_cve_id("CVE-2019-15052", "CVE-2021-29429");
  script_tag(name:"creation_date", value:"2024-04-06 01:04:16 +0000 (Sat, 06 Apr 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-29 16:01:46 +0000 (Thu, 29 Aug 2019)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:1119-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1119-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241119-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184799");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-April/034851.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gradle, gradle-bootstrap' package(s) announced via the SUSE-SU-2024:1119-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gradle, gradle-bootstrap fixes the following issues:

- CVE-2021-29429: Fixed information disclosure through temporary directory permissions (bsc#1184799).
- CVE-2019-15052: Fixed authentication credentials disclosure (bsc#1145903).

gradle:

- Fixed RPM package building issues due to changed dependencies

gradle-bootstrap:

- Added missing dependency of aopalliance");

  script_tag(name:"affected", value:"'gradle, gradle-bootstrap' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"gpars-bootstrap", rpm:"gpars-bootstrap~1.2.1~150200.3.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gradle", rpm:"gradle~4.4.1~150200.3.15.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gradle-bootstrap", rpm:"gradle-bootstrap~4.4.1~150200.3.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"groovy-bootstrap", rpm:"groovy-bootstrap~2.4.21~150200.3.9.1", rls:"openSUSELeap15.5"))) {
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
