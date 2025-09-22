# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856895");
  script_cve_id("CVE-2024-24815");
  script_tag(name:"creation_date", value:"2025-01-08 05:00:06 +0000 (Wed, 08 Jan 2025)");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-15 15:09:37 +0000 (Thu, 15 Feb 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2025:0008-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0008-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ZXNT2JPQVYWDQRDN2YJ7KJCRBY5QEJQW/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219720");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django-ckeditor' package(s) announced via the openSUSE-SU-2025:0008-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-django-ckeditor fixes the following issues:

- Update to 6.7.2
 * Deprecated the package.
 * Added a new ckeditor/fixups.js script which disables the version check again
 (if something slips through by accident) and which disables the behavior
 where CKEditor 4 would automatically attach itself to unrelated HTML elements
 with a contenteditable attribute (see CKEDITOR.disableAutoInline in the
 CKEditor 4 docs).
- CVE-2024-24815: Fixed bypass of Advanced Content Filtering mechanism (boo#1219720)

- update to 6.7.1:
 * Add Python 3.12, Django 5.0
 * Silence the CKEditor version check/nag but include a system check warning

- update to 6.7.0:
 * Dark mode fixes.
 * Added support for Pillow 10.

- update to 6.6.1:
 * Required a newer version of django-js-asset which actually works
 with Django 4.1.
 * CKEditor 4.21.0
 * Fixed the CKEditor styles when used with the dark Django admin theme.

- update to 6.5.1:
 * Avoided calling ``static()`` if ``CKEDITOR_BASEPATH`` is defined.
 * Fixed ``./manage.py generateckeditorthumbnails`` to work again after the
 image uploader backend rework.
 * CKEditor 4.19.1
 * Stopped calling ``static()`` during application startup.
 * Added Django 4.1
 * Changed the context for the widget to deviate less from Django. Removed a
 * few template variables which are not used in the bundled
 * ``ckeditor/widget.html`` template. This only affects you if you are using a
 * customized widget or widget template.
 * Dropped support for Python < 3.8, Django < 3.2.
 * Added a pre-commit configuration.
 * Added a GitHub action for running tests.
 * Made selenium tests require opt in using a ``SELENIUM=firefox`` or
 ``SELENIUM=chromium`` environment variable.
 * Made it possible to override the CKEditor template in the widget class.
 * Changed ``CKEDITOR_IMAGE_BACKEND`` to require dotted module paths (the old
 identifiers are still supported for now).");

  script_tag(name:"affected", value:"'python-django-ckeditor' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"python311-django-ckeditor", rpm:"python311-django-ckeditor~6.7.2~bp155.3.3.1", rls:"openSUSELeap15.5"))) {
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
