# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63482");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-03-07 21:47:03 +0100 (Sat, 07 Mar 2009)");
  script_cve_id("CVE-2007-4850", "CVE-2008-5557", "CVE-2009-0754");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mandrake Security Advisory MDVSA-2009:065 (php4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_4\.0");
  script_tag(name:"insight", value:"A vulnerability in the cURL library in PHP allowed context-dependent
attackers to bypass safe_mode and open_basedir restrictions and read
arbitrary files using a special URL request (CVE-2007-4850).

improve mbfl_filt_conv_html_dec_flush() error handling in
ext/mbstring/libmbfl/filters/mbfilter_htmlent.c (CVE-2008-5557).

PHP 4.4.4, 5.1.6, and other versions, when running on Apache, allows
local users to modify behavior of other sites hosted on the same
web server by modifying the mbstring.func_overload setting within
.htaccess, which causes this setting to be applied to other virtual
hosts on the same server (CVE-2009-0754).

The updated packages have been patched to correct these issues.

Affected: Corporate 4.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:065");
  script_tag(name:"summary", value:"The remote host is missing an update to php4
announced via advisory MDVSA-2009:065.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"libphp4_common4", rpm:"libphp4_common4~4.4.4~1.10.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php4-cgi", rpm:"php4-cgi~4.4.4~1.10.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php4-cli", rpm:"php4-cli~4.4.4~1.10.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php4-curl", rpm:"php4-curl~4.4.4~1.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php4-devel", rpm:"php4-devel~4.4.4~1.10.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php4-mbstring", rpm:"php4-mbstring~4.4.4~1.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64php4_common4", rpm:"lib64php4_common4~4.4.4~1.10.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
