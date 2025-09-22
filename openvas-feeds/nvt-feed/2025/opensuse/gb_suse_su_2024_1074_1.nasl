# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.1074.1");
  script_cve_id("CVE-2019-0223");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-22 20:09:23 +0000 (Fri, 22 Apr 2022)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:1074-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1074-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241074-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1041090");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084627");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172267");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191783");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-April/034819.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qpid-proton' package(s) announced via the SUSE-SU-2024:1074-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qpid-proton fixes the following issues:

- CVE-2019-0223: Fixed TLS Man in the Middle Vulnerability (bsc#1133158).

The following non-security bugs were fixed:

- Fix build with OpenSSL 3.0.0 (bsc#1172267)
- Sort linked .o files to make package build reproducible (bsc#1041090)
- Fix build with gcc8 (bsc#1084627)
- Move libqpid-proton-core to a different package to fix a rpmlint
 error (bsc#1191783)");

  script_tag(name:"affected", value:"'qpid-proton' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"python3-python-qpid-proton", rpm:"python3-python-qpid-proton~0.38.0~150000.6.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qpid-proton-devel", rpm:"qpid-proton-devel~0.38.0~150000.6.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qpid-proton-devel-doc", rpm:"qpid-proton-devel-doc~0.38.0~150000.6.3.1", rls:"openSUSELeap15.5"))) {
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
