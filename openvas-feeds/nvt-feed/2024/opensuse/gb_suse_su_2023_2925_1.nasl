# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833513");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-24834", "CVE-2022-36021", "CVE-2023-25155", "CVE-2023-28425", "CVE-2023-28856", "CVE-2023-36824");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-20 12:56:44 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:58:19 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for redis7 (SUSE-SU-2023:2925-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2925-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/MOHYQFQCHUOXKLW5W46XUWCPEZG6YNQB");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'redis7'
  package(s) announced via the SUSE-SU-2023:2925-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for redis7 fixes the following issues:

  * CVE-2022-24834: Fixed heap overflow in the cjson and cmsgpack libraries
      (bsc#1213193).

  * CVE-2023-28856: Fixed HINCRBYFLOAT invalid key crash (bsc#1210548).

  * CVE-2022-36021: Fixed integer overflow via Specially crafted SRANDMEMBER,
      ZRANDMEMBER, and HRANDFIELD (bsc#1208790).

  * CVE-2023-25155: Fixed Integer Overflow in RAND commands (bsc#1208793).

  * CVE-2023-28425: Fixed denial-of-service via Specially crafted MSETNX command
      (bsc#1209528).

  * CVE-2023-36824: Fixed heap overflow in COMMAND GETKEYS and ACL evaluation
      (bsc#1213249).

  ##");

  script_tag(name:"affected", value:"'redis7' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"redis7", rpm:"redis7~7.0.8~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis7-debuginfo", rpm:"redis7-debuginfo~7.0.8~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis7-debugsource", rpm:"redis7-debugsource~7.0.8~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis7", rpm:"redis7~7.0.8~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis7-debuginfo", rpm:"redis7-debuginfo~7.0.8~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis7-debugsource", rpm:"redis7-debugsource~7.0.8~150500.3.3.1", rls:"openSUSELeap15.5"))) {
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