# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.72523");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2012-2859", "CVE-2012-2860", "CVE-2012-2865", "CVE-2012-2866", "CVE-2012-2867", "CVE-2012-2868", "CVE-2012-2869", "CVE-2012-2872", "CVE-2012-2874", "CVE-2012-2876", "CVE-2012-2877", "CVE-2012-2878", "CVE-2012-2879", "CVE-2012-2880", "CVE-2012-2881", "CVE-2012-2882", "CVE-2012-2883", "CVE-2012-2884", "CVE-2012-2885", "CVE-2012-2886", "CVE-2012-2887", "CVE-2012-2888", "CVE-2012-2889", "CVE-2012-2891", "CVE-2012-2892", "CVE-2012-2894", "CVE-2012-2896", "CVE-2012-2900", "CVE-2012-5108", "CVE-2012-5110", "CVE-2012-5111", "CVE-2012-5112", "CVE-2012-5376");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-27 17:19:00 +0000 (Fri, 27 Sep 2019)");
  script_tag(name:"creation_date", value:"2012-10-22 08:43:44 -0400 (Mon, 22 Oct 2012)");
  script_name("Gentoo Security Advisory GLSA 201210-07 (chromium)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been reported in Chromium, some of
    which may allow execution of arbitrary code.");
  script_tag(name:"solution", value:"All Chromium users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-client/chromium-22.0.1229.94'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201210-07");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=433551");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=436234");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=437664");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=437984");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2012/08/stable-channel-update_30.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2012/09/stable-channel-update_25.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2012/10/stable-channel-update.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2012/10/stable-channel-update_6105.html");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201210-07.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"www-client/chromium", unaffected: make_list("ge 22.0.1229.94"), vulnerable: make_list("lt 22.0.1229.94"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
