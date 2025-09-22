# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833129");
  script_cve_id("CVE-2023-48795");
  script_tag(name:"creation_date", value:"2024-03-04 12:51:23 +0000 (Mon, 04 Mar 2024)");
  script_version("2025-02-26T05:38:40+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:40 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-28 18:26:44 +0000 (Thu, 28 Dec 2023)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0036-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0036-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/UXSOYCFCX44QUQ434BAHHQRSSCB3KZG5/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218197");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tinyssh' package(s) announced via the openSUSE-SU-2024:0036-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tinyssh fixes the following issues:

tinyssh was updated to 20240101 (boo#1218197, CVE-2023-48795):

 * fixed channel_forkpty() race condition between close(slave)
 in parent process and login_tty(slave) in child process
 * fixed behavior when using terminal mode and stdin redirected
 to /dev/null 'ssh -tt -n'
 * added an 'strict-key' key exchange kex-strict-
 s-v00@openssh.com (Mitigates CVE-2023-48795 'Terrapin
 attack')");

  script_tag(name:"affected", value:"'tinyssh' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"tinyssh", rpm:"tinyssh~20240101~bp155.2.3.1", rls:"openSUSELeap15.5"))) {
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
