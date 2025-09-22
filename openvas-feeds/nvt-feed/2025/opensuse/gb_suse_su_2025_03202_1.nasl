# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.03202.1");
  script_cve_id("CVE-2025-58068");
  script_tag(name:"creation_date", value:"2025-09-15 04:06:57 +0000 (Mon, 15 Sep 2025)");
  script_version("2025-09-15T05:39:20+0000");
  script_tag(name:"last_modification", value:"2025-09-15 05:39:20 +0000 (Mon, 15 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:03202-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03202-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503202-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248994");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041684.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-eventlet' package(s) announced via the SUSE-SU-2025:03202-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-eventlet fixes the following issues:

- CVE-2025-58068: improper handling of HTTP trailer sections in WSGI parser leads to HTTP request smuggling
 (bsc#1248994).");

  script_tag(name:"affected", value:"'python-eventlet' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"python311-eventlet", rpm:"python311-eventlet~0.33.3~150400.5.6.1", rls:"openSUSELeap15.6"))) {
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
