# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0440.1");
  script_cve_id("CVE-2025-13473", "CVE-2025-14550", "CVE-2026-1207", "CVE-2026-1285", "CVE-2026-1287", "CVE-2026-1312");
  script_tag(name:"creation_date", value:"2026-02-13 04:40:02 +0000 (Fri, 13 Feb 2026)");
  script_version("2026-02-13T05:57:48+0000");
  script_tag(name:"last_modification", value:"2026-02-13 05:57:48 +0000 (Fri, 13 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0440-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0440-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260440-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257403");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257405");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257406");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257407");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257408");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024108.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-Django' package(s) announced via the SUSE-SU-2026:0440-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-Django fixes the following issues:

- CVE-2025-14550: Fixed potential denial-of-service via repeated
 headers when using ASGI(bsc#1257403)
- CVE-2026-1312: Fixed potential SQL injection via QuerySet.order_by
 and FilteredRelation (bsc#1257408)
- CVE-2026-1287: Fixed potential SQL injection in column aliases
 via control characters (bsc#1257407)
- CVE-2026-1207: Fixed potential SQL injection via raster lookups
 on PostGIS (bsc#1257405)
- CVE-2025-13473: Fixed username enumeration through timing difference
 in mod_wsgi authentication handler (bsc#1257401)
- CVE-2026-1285: Fixed potential denial-of-service in
 django.utils.text.Truncator HTML methods (bsc#1257406)");

  script_tag(name:"affected", value:"'python-Django' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"python311-Django", rpm:"python311-Django~4.2.11~150600.3.47.1", rls:"openSUSELeap15.6"))) {
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
