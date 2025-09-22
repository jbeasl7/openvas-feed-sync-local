# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66490");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2009-12-14 23:06:43 +0100 (Mon, 14 Dec 2009)");
  script_cve_id("CVE-2009-2659", "CVE-2009-3695");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Mandriva Security Advisory MDVSA-2009:276-1 (python-django)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_2008\.0");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been found and corrected in python-django:

The Admin media handler in core/servers/basehttp.py in Django 1.0
and 0.96 does not properly map URL requests to expected static media
files, which allows remote attackers to conduct directory traversal
attacks and read arbitrary files via a crafted URL (CVE-2009-2659).

Algorithmic complexity vulnerability in the forms library in Django
1.0 before 1.0.4 and 1.1 before 1.1.1 allows remote attackers to cause
a denial of service (CPU consumption) via a crafted (1) EmailField
(email address) or (2) URLField (URL) that triggers a large amount
of backtracking in a regular expression (CVE-2009-3695).

The versions of Django shipping with Mandriva Linux have been updated
to the latest patched version that include the fix for this issue.
In addition, they provide other bug fixes.

Update:

Packages for 2008.0 are being provided due to extended support for
Corporate products.

Affected: 2008.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:276-1");
  script_xref(name:"URL", value:"http://www.djangoproject.com/weblog/2009/jul/28/security/");
  script_xref(name:"URL", value:"http://www.djangoproject.com/weblog/2009/oct/09/security/");
  script_tag(name:"summary", value:"The remote host is missing an update to python-django
announced via advisory MDVSA-2009:276-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"python-django", rpm:"python-django~1.0.4~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
