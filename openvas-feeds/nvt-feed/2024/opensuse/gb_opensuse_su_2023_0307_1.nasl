# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833240");
  script_version("2025-04-25T15:41:53+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-25 15:41:53 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"creation_date", value:"2024-03-04 07:15:01 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for bluetuith (openSUSE-SU-2023:0307-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0307-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XURBPTX7HZIVH2DJR4DNKE2BL4MXQEKL");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bluetuith'
  package(s) announced via the openSUSE-SU-2023:0307-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for bluetuith fixes the following issues:

  - Update to 0.1.7:

  * New HJSON-based configuration format

  * Adapter status indicators

  * Cancellable OBEX session creation

  * Enhanced popups

  * Major bugfixes and improvements

  - Update to 0.1.5:

  * ui: device: Show address if name is empty

  * agent: Display pincode in a modal #14

  - Update to 0.1.5:

  * Update dependencies to resolve vulnerability

  - Update to 0.1.4:

  * Minor bugfixes");

  script_tag(name:"affected", value:"'bluetuith' package(s) on openSUSE Backports SLE-15-SP5.");

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

if(release == "openSUSEBackportsSLE-15-SP5") {

  if(!isnull(res = isrpmvuln(pkg:"bluetuith", rpm:"bluetuith~0.1.7~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluetuith", rpm:"bluetuith~0.1.7~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
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
