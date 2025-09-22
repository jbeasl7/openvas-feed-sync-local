# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0039");
  script_cve_id("CVE-2024-38875", "CVE-2024-39329", "CVE-2024-39330", "CVE-2024-39614", "CVE-2024-41989", "CVE-2024-41990", "CVE-2024-41991", "CVE-2024-42005", "CVE-2024-45230", "CVE-2024-45231", "CVE-2024-53907", "CVE-2024-53908", "CVE-2024-56374");
  script_tag(name:"creation_date", value:"2025-02-06 04:12:21 +0000 (Thu, 06 Feb 2025)");
  script_version("2025-02-06T05:38:57+0000");
  script_tag(name:"last_modification", value:"2025-02-06 05:38:57 +0000 (Thu, 06 Feb 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-19 00:53:40 +0000 (Sat, 19 Oct 2024)");

  script_name("Mageia: Security Advisory (MGASA-2025-0039)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0039");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0039.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33387");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33507");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33919");
  script_xref(name:"URL", value:"https://openwall.com/lists/oss-security/2024/08/06/2");
  script_xref(name:"URL", value:"https://openwall.com/lists/oss-security/2024/12/04/3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7205-1");
  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2024/jul/09/security-releases/");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/07/09/3");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/09/03/3");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/01/14/2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django' package(s) announced via the MGASA-2025-0039 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in Django 4.2 before 4.2.14 and 5.0 before
5.0.7. urlize and urlizetrunc were subject to a potential denial of
service attack via certain inputs with a very large number of brackets.
(CVE-2024-38875)
An issue was discovered in Django 5.0 before 5.0.7 and 4.2 before
4.2.14. The django.contrib.auth.backends.ModelBackend.authenticate()
method allows remote attackers to enumerate users via a timing attack
involving login requests for users with an unusable password.
(CVE-2024-39329)
An issue was discovered in Django 5.0 before 5.0.7 and 4.2 before
4.2.14. Derived classes of the django.core.files.storage.Storage base
class, when they override generate_filename() without replicating the
file-path validations from the parent class, potentially allow directory
traversal via certain inputs during a save() call. (CVE-2024-39330)
An issue was discovered in Django 5.0 before 5.0.7 and 4.2 before
4.2.14. get_supported_language_variant() was subject to a potential
denial-of-service attack when used with very long strings containing
specific characters. (CVE-2024-39614)
An issue was discovered in Django 5.0 before 5.0.8 and 4.2 before
4.2.15. The floatformat template filter is subject to significant memory
consumption when given a string representation of a number in scientific
notation with a large exponent. (CVE-2024-41989)
An issue was discovered in Django 5.0 before 5.0.8 and 4.2 before
4.2.15. The urlize() and urlizetrunc() template filters are subject to a
potential denial-of-service attack via very large inputs with a specific
sequence of characters. (CVE-2024-41990)
An issue was discovered in Django 5.0 before 5.0.8 and 4.2 before
4.2.15. The urlize and urlizetrunc template filters, and the
AdminURLFieldWidget widget, are subject to a potential denial-of-service
attack via certain inputs with a very large number of Unicode
characters. (CVE-2024-41991)
An issue was discovered in Django 5.0 before 5.0.8 and 4.2 before
4.2.15. QuerySet.values() and values_list() methods on models with a
JSONField are subject to SQL injection in column aliases via a crafted
JSON object key as a passed *arg. (CVE-2024-42005)
An issue was discovered in Django 5.1 before 5.1.1, 5.0 before 5.0.9,
and 4.2 before 4.2.16. The urlize() and urlizetrunc() template filters
are subject to a potential denial-of-service attack via very large
inputs with a specific sequence of characters. (CVE-2024-45230)
An issue was discovered in Django v5.1.1, v5.0.9, and v4.2.16. The
django.contrib.auth.forms.PasswordResetForm class, when used in a view
implementing password reset flows, allows remote attackers to enumerate
user e-mail addresses by sending password reset requests and observing
the outcome (only when e-mail sending is consistently failing).
(CVE-2024-45231)
An issue was discovered in Django 5.1 before 5.1.4, 5.0 before 5.0.10,
and 4.2 before 4.2.17. The strip_tags() method and striptags ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'python-django' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"python-django", rpm:"python-django~4.1.13~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-django", rpm:"python3-django~4.1.13~1.2.mga9", rls:"MAGEIA9"))) {
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
