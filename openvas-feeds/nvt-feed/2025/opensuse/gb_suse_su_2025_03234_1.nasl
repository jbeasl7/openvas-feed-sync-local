# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.03234.1");
  script_cve_id("CVE-2025-50200");
  script_tag(name:"creation_date", value:"2025-09-18 04:06:35 +0000 (Thu, 18 Sep 2025)");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-06 18:28:43 +0000 (Wed, 06 Aug 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:03234-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03234-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503234-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246091");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041709.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rabbitmq-server313' package(s) announced via the SUSE-SU-2025:03234-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rabbitmq-server313 fixes the following issues:

- CVE-2025-50200: Fixed logging of Basic Auth header from an HTTP request
 (bsc#1245105)
- Fixed bad logrotate configuration allowing potential escalation from
 rabbitmq to root (bsc#1246091)");

  script_tag(name:"affected", value:"'rabbitmq-server313' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"erlang-rabbitmq-client313", rpm:"erlang-rabbitmq-client313~3.13.1~150600.13.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rabbitmq-server313", rpm:"rabbitmq-server313~3.13.1~150600.13.11.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rabbitmq-server313-plugins", rpm:"rabbitmq-server313-plugins~3.13.1~150600.13.11.1", rls:"openSUSELeap15.6"))) {
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
