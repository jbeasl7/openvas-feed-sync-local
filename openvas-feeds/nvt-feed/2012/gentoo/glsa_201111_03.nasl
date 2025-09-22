# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70792");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-4168", "CVE-2011-3341", "CVE-2011-3342", "CVE-2011-3343");
  script_version("2024-02-05T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-05 05:05:38 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 16:40:58 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-02-12 10:04:40 -0500 (Sun, 12 Feb 2012)");
  script_name("Gentoo Security Advisory GLSA 201111-03 (ebuild OpenTTD)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities were found in OpenTTD which could lead to
    execution of arbitrary code, a Denial of Service, or privilege
escalation.");
  script_tag(name:"solution", value:"All OpenTTD users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=games-simulation/openttd-1.1.3'


NOTE: This is a legacy GLSA. Updates for all affected architectures are
      available since September 27, 2011. It is likely that your system is
      already no longer affected by this issue.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201111-03");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=381799");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201111-03.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"games-simulation/openttd", unaffected: make_list("ge 1.1.3"), vulnerable: make_list("lt 1.1.3"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
