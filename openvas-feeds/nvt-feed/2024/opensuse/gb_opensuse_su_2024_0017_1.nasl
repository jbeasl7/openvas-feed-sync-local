# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833479");
  script_cve_id("CVE-2021-46898");
  script_tag(name:"creation_date", value:"2024-03-04 12:55:34 +0000 (Mon, 04 Mar 2024)");
  script_version("2025-02-26T05:38:40+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:40 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-30 15:56:43 +0000 (Mon, 30 Oct 2023)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0017-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0017-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3GF4HWC4HAGFXA56AYL7TL7B3KA2SM45/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216481");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django-grappelli' package(s) announced via the openSUSE-SU-2024:0017-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-django-grappelli fixes the following issues:

Update to 2.14.4:

- CVE-2021-46898: Fixed views/switch.py vulnerable to protocol-relative URL attacks (boo#1216481)
- Fixed: Redirect with switch user.
- Improved: Remove extra filtering in AutocompleteLookup.
- Improved: Added import statement with URLs for quickstart docs.
- Improved: Added additional blocks with inlines to allow override.
- Fixed: Compatibility with Django 3.1.
- Fixed: Docs about adding Grappelli documentation URLS.");

  script_tag(name:"affected", value:"'python-django-grappelli' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"python3-django-grappelli", rpm:"python3-django-grappelli~2.14.4~bp155.3.3.1", rls:"openSUSELeap15.5"))) {
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
