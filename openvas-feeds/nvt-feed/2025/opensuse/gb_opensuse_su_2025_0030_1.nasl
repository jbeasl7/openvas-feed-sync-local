# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2025.0030.1");
  script_cve_id("CVE-2024-54662");
  script_tag(name:"creation_date", value:"2025-02-18 11:01:57 +0000 (Tue, 18 Feb 2025)");
  script_version("2025-02-20T08:47:14+0000");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (openSUSE-SU-2025:0030-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0030-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/IWNRHV4HZ3KU4VHYWJQPULNK5D444I3X/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234688");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dante' package(s) announced via the openSUSE-SU-2025:0030-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dante fixes the following issues:

- Update to version 1.4.4
 * Fixed incorrect access control for some sockd.conf configurations
 involving socksmethod (boo#1234688, CVE-2024-54662).");

  script_tag(name:"affected", value:"'dante' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"dante", rpm:"dante~1.4.4~bp156.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dante-devel", rpm:"dante-devel~1.4.4~bp156.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dante-devel-64bit", rpm:"dante-devel-64bit~1.4.4~bp156.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dante-server", rpm:"dante-server~1.4.4~bp156.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsocks0", rpm:"libsocks0~1.4.4~bp156.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsocks0-64bit", rpm:"libsocks0-64bit~1.4.4~bp156.4.3.1", rls:"openSUSELeap15.6"))) {
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
