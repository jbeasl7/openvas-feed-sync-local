# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0855.1");
  script_cve_id("CVE-2026-27727", "CVE-2026-27830");
  script_tag(name:"creation_date", value:"2026-03-11 12:46:59 +0000 (Wed, 11 Mar 2026)");
  script_version("2026-03-13T05:54:58+0000");
  script_tag(name:"last_modification", value:"2026-03-13 05:54:58 +0000 (Fri, 13 Mar 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-11 23:30:53 +0000 (Wed, 11 Mar 2026)");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0855-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0855-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260855-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258913");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259313");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024666.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'c3p0 and mchange-commons' package(s) announced via the SUSE-SU-2026:0855-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for c3p0 and mchange-commons fixes the following issues:

c3p0:

- Security issues fixed:

 - CVE-2026-27830: Fixed unsafe object deserialization (bsc#1258942)

- Fix the null pointer exception in the userOverridesAsString
 method (bsc#1259313).

mchange-commons:

- Security issues fixed:

 - CVE-2026-27727: Disabled remote ClassLoading when dereferencing javax.naming.Reference instances (bsc#1258913)");

  script_tag(name:"affected", value:"'c3p0 and mchange-commons' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"c3p0", rpm:"c3p0~0.9.5.5~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"c3p0-javadoc", rpm:"c3p0-javadoc~0.9.5.5~150400.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mchange-commons", rpm:"mchange-commons~0.2.20~150400.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mchange-commons-javadoc", rpm:"mchange-commons-javadoc~0.2.20~150400.3.3.1", rls:"openSUSELeap15.6"))) {
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
