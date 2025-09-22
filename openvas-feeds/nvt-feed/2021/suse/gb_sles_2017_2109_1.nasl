# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2109.1");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:54 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2109-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2109-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172109-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049488");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049489");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049490");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049491");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-August/003122.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tcmu-runner' package(s) announced via the SUSE-SU-2017:2109-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tcmu-runner fixes the following issues:

- qcow handler opens up an information leak via the CheckConfig D-Bus method (bsc#1049491)
- glfs handler allows local DoS via crafted CheckConfig strings (bsc#1049485)
- UnregisterHandler dbus method in tcmu-runner daemon for non-existing handler causes denial of service (bsc#1049488)
- UnregisterHandler D-Bus method in tcmu-runner daemon for internal handler causes denial of service (bsc#1049489)
- Memory leaks can be triggered in tcmu-runner daemon by calling D-Bus method for (Un)RegisterHandler (bsc#1049490)");

  script_tag(name:"affected", value:"'tcmu-runner' package(s) on SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libtcmu1", rpm:"libtcmu1~1.2.0~2.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tcmu-runner", rpm:"tcmu-runner~1.2.0~2.3.1", rls:"SLES12.0SP3"))) {
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
