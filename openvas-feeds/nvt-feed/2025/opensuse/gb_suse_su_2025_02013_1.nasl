# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.02013.1");
  script_cve_id("CVE-2025-6018", "CVE-2025-6020");
  script_tag(name:"creation_date", value:"2025-06-20 04:11:07 +0000 (Fri, 20 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-17 13:15:21 +0000 (Tue, 17 Jun 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:02013-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02013-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502013-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244509");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-June/040370.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pam' package(s) announced via the SUSE-SU-2025:02013-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for pam fixes the following issues:

- CVE-2025-6018: pam_env: Change the default to not read the user .pam_environment file (bsc#1243226).
- CVE-2025-6020: pam_namespace: convert functions that may operate on a user-controlled path to operate on file descriptors instead of absolute path (bsc#1244509).");

  script_tag(name:"affected", value:"'pam' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"pam", rpm:"pam~1.3.0~150000.6.83.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-32bit", rpm:"pam-32bit~1.3.0~150000.6.83.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-devel", rpm:"pam-devel~1.3.0~150000.6.83.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-devel-32bit", rpm:"pam-devel-32bit~1.3.0~150000.6.83.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-doc", rpm:"pam-doc~1.3.0~150000.6.83.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-extra", rpm:"pam-extra~1.3.0~150000.6.83.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-extra-32bit", rpm:"pam-extra-32bit~1.3.0~150000.6.83.1", rls:"openSUSELeap15.6"))) {
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
