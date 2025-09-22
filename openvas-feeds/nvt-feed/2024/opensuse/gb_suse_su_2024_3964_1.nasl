# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856715");
  script_cve_id("CVE-2024-50602");
  script_tag(name:"creation_date", value:"2024-11-11 08:47:50 +0000 (Mon, 11 Nov 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:3964-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3964-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243964-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228252");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232590");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-November/019803.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-wxPython' package(s) announced via the SUSE-SU-2024:3964-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-wxPython fixes the following issues:

Security issue fixed:

- CVE-2024-50602: Fixed a denial of service in the vendored libexpat's XML_ResumeParser function (bsc#1232590).

Non-security issues fixed:

- rebuilt for python 3.11 (bsc#1228252).
- add repack script, do not include packaging/ dir in sources
- Reduce complexity by not rewriting subpackages at all.
- Appease factory-auto bot about package src name.
- Add additional patches fixing the situation with Python 3.10
 compatibility.
- Split out the TW python3 flavors into multibuild using the
 python_subpackage_only mechanism: Multiple python3 flavors
 sequentially require too much space and time in one build.");

  script_tag(name:"affected", value:"'python-wxPython' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"python311-wxPython", rpm:"python311-wxPython~4.1.1~150400.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-wxPython-lang", rpm:"python311-wxPython-lang~4.1.1~150400.3.8.1", rls:"openSUSELeap15.6"))) {
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
