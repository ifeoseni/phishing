#!/usr/bin/env python3
import os
import re
import pandas as pd
import tldextract
from urllib.parse import urlparse, unquote
from datetime import datetime
import math
import argparse
import logging

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# --- Constants ---
SUSPICIOUS_TLDS = ['biz', 'buzz', 'cf', 'club', 'cn', 'com', 'ga', 'gq', 'host', 'icu', 'info', 'live', 'ml', 'name', 'net', 'online', 'org', 'ru', 'tk', 'top', 'us', 'wang', 'ws', 'xyz']
# Known shortening services
# SHORTENING_SERVICES = {
#     'bit.ly', 't.co', 'goo.gl', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly',
#     'j.mp', 'youtu.be', 'rebrand.ly', 'tiny.cc', 'lc.chat', 'rb.gy'
# }
SHORTENING_SERVICES = {
    '0.gp', '02faq.com', '0a.sk', '101.gg', '12ne.ws', '17mimei.club', '1drv.ms', '1ea.ir', '1kh.de', '1o2.ir', '1shop.io', '1u.fi', '1un.fr', '1url.cz', '2.gp', '2.ht', '2.ly', '2doc.net', '2fear.com', '2kgam.es', '2link.cc', '2nu.gs', '2pl.us', '2u.lc', '2u.pw', '2wsb.tv', '3.cn', '3.ly', '301.link', '3le.ru', '4.gp', '4.ly', '49rs.co', '4sq.com', '5.gp', '52.nu', '53eig.ht', '5du.pl', '5w.fit', '6.gp', '6.ly', '69run.fun', '6g6.eu', '7.ly', '707.su', '71a.xyz', '7news.link', '7ny.tv', '7oi.de', '8.ly', '89q.sk', '8fig.me', '92url.com', '985.so', '98pro.cc', '9mp.com', '9splay.store', 'a.189.cn', 'a.co', 'a360.co', 'aarp.info', 'ab.co', 'abc.li', 'abc11.tv', 'abc13.co', 'abc7.la', 'abc7.ws', 'abc7ne.ws', 'abcn.ws', 'abe.ma', 'abelinc.me', 'abnb.me', 'abr.ai', 'abre.ai', 'accntu.re', 'accu.ps', 'acer.co', 'acer.link', 'aces.mp', 'acortar.link', 'act.gp', 'acus.org', 'adaymag.co', 'adb.ug', 'adbl.co', 'adf.ly', 'adfoc.us', 'adm.to', 'adobe.ly', 'adol.us', 'adweek.it', 'aet.na', 'agrd.io', 'ai6.net', 'aje.io', 'aka.ms', 'al.st', 'alexa.design', 'alli.pub', 'alnk.to', 'alpha.camp', 'alphab.gr', 'alturl.com', 'amays.im', 'amba.to', 'amc.film', 'amex.co', 'ampr.gs', 'amrep.org', 'amz.run', 'amzn.com', 'amzn.pw', 'amzn.to', 'ana.ms', 'anch.co', 'ancstry.me', 'andauth.co', 'anon.to', 'anyimage.io', 'aol.it', 'aon.io', 'apne.ws', 'app.philz.us', 'apple.co', 'apple.news', 'aptg.tw', 'arah.in', 'arc.ht', 'arkinv.st', 'asics.tv', 'asin.cc', 'asq.kr', 'asus.click', 'at.vibe.com', 'atm.tk', 'atmilb.com', 'atmlb.com', 'atres.red', 'autode.sk', 'avlne.ws', 'avlr.co', 'avydn.co', 'axios.link', 'axoni.us', 'ay.gy', 'azc.cc', 'b-gat.es', 'b.link', 'b.mw', 'b23.ru', 'b23.tv', 'b2n.ir', 'baratun.de', 'bayareane.ws', 'bbc.in', 'bbva.info', 'bc.vc', 'bca.id', 'bcene.ws', 'bcove.video', 'bcsite.io', 'bddy.me', 'beats.is', 'benqurl.biz', 'beth.games', 'bfpne.ws', 'bg4.me', 'bhpho.to', 'bigcc.cc', 'bigfi.sh', 'biggo.tw', 'biibly.com', 'binged.it', 'bit.ly', 'bitly.com', 'bitly.is', 'bitly.lc', 'bityl.co', 'bl.ink', 'blap.net', 'blbrd.cm', 'blck.by', 'blizz.ly', 'bloom.bg', 'blstg.news', 'blur.by', 'bmai.cc', 'bnds.in', 'bnetwhk.com', 'bo.st', 'boa.la', 'boile.rs', 'bom.so', 'bonap.it', 'booki.ng', 'bookstw.link', 'bose.life', 'boston25.com', 'bp.cool', 'br4.in', 'bravo.ly', 'bridge.dev', 'brief.ly', 'brook.gs', 'browser.to', 'bst.bz', 'bstk.me', 'btm.li', 'btwrdn.com', 'budurl.com', 'buff.ly', 'bung.ie', 'bwnews.pr', 'by2.io', 'bytl.fr', 'bzfd.it', 'bzh.me', 'c11.kr', 'c87.to', 'cadill.ac', 'can.al', 'canon.us', 'capital.one', 'capitalfm.co', 'captl1.co', 'careem.me', 'caro.sl', 'cart.mn', 'casio.link', 'cathaybk.tw', 'cathaysec.tw', 'cb.com', 'cbj.co', 'cbsloc.al', 'cbsn.ws', 'cbt.gg', 'cc.cc', 'cdl.booksy.com', 'cfl.re', 'chip.tl', 'chl.li', 'chn.ge', 'chn.lk', 'chng.it', 'chts.tw', 'chzb.gr', 'cin.ci', 'cindora.club', 'circle.ci', 'cirk.me', 'cisn.co', 'citi.asia', 'cjky.it', 'ckbe.at', 'cl.ly', 'clarobr.co', 'clc.am', 'clc.to', 'clck.ru', 'cle.clinic', 'cli.re', 'clickmeter.com', 'clicky.me', 'clr.tax', 'clvr.rocks', 'cmon.co', 'cmu.is', 'cmy.tw', 'cna.asia', 'cnb.cx', 'cnet.co', 'cnfl.io', 'cnn.it', 'cnnmon.ie', 'cnvrge.co', 'cockroa.ch', 'comca.st', 'conta.cc', 'cookcenter.info', 'coop.uk', 'cort.as', 'coupa.ng', 'cplink.co', 'cr8.lv', 'crackm.ag', 'crdrv.co', 'credicard.biz', 'crwd.fr', 'crwd.in', 'crwdstr.ke', 'cs.co', 'csmo.us', 'cstu.io', 'ctbc.tw', 'ctfl.io', 'cultm.ac', 'cup.org', 'cut.lu', 'cut.pe', 'cutt.ly', 'cvent.me', 'cvs.co', 'cyb.ec', 'cybr.rocks', 'd-sh.io', 'da.gd', 'dai.ly', 'dailym.ai', 'dainik-b.in', 'datayi.cn', 'davidbombal.wiki', 'db.tt', 'dbricks.co', 'dcps.co', 'dd.ma', 'deb.li', 'dee.pl', 'deli.bz', 'dell.to', 'deloi.tt', 'dems.me', 'dhk.gg', 'di.sn', 'dibb.me', 'dis.gd', 'dis.tl', 'discord.gg', 'discvr.co', 'disq.us', 'dive.pub', 'djex.co', 'dk.rog.gg', 'dkng.co', 'dky.bz', 'dl.gl', 'dld.bz', 'dlsh.it', 'dlvr.it', 'dmdi.pl', 'dmreg.co', 'do.co', 'dockr.ly', 'dopice.sk', 'dpmd.ai', 'dpo.st', 'dssurl.com', 'dtdg.co', 'dtsx.io', 'dub.sh', 'dv.gd', 'dvrv.ai', 'dw.com', 'dwz.tax', 'dxc.to', 'dy.fi', 'dy.si', 'e.lilly', 'e.vg', 'ebay.to', 'econ.st', 'ed.gr', 'edin.ac', 'edu.nl', 'eepurl.com', 'efshop.tw', 'ela.st', 'elle.re', 'ellemag.co', 'embt.co', 'emirat.es', 'engt.co', 'enshom.link', 'entm.ag', 'envs.sh', 'epochtim.es', 'ept.ms', 'eqix.it', 'es.pn', 'es.rog.gg', 'escape.to', 'esl.gg', 'eslite.me', 'esqr.co', 'esun.co', 'etoro.tw', 'etp.tw', 'etsy.me', 'everri.ch', 'exe.io', 'exitl.ag', 'ezstat.ru', 'f1.com', 'f5yo.com', 'fa.by', 'fal.cn', 'fam.ag', 'fandan.co', 'fandom.link', 'fandw.me', 'faras.link', 'faturl.com', 'fav.me', 'fave.co', 'fb.me', 'fb.watch', 'fbstw.link', 'fce.gg', 'fetnet.tw', 'fevo.me', 'ff.im', 'fifa.fans', 'firsturl.de', 'firsturl.net', 'flic.kr', 'flip.it', 'flomuz.io', 'flq.us', 'fltr.ai', 'flx.to', 'fmurl.cc', 'fn.gg', 'fnb.lc', 'foodtv.com', 'fooji.info', 'ford.to', 'forms.gle', 'forr.com', 'found.ee', 'fox.tv', 'fr.rog.gg', 'frdm.mobi', 'fstrk.cc', 'ftnt.net', 'fumacrom.com', 'fvrr.co', 'fwme.eu', 'fxn.ws', 'g-web.in', 'g.asia', 'g.co', 'g.page', 'ga.co', 'galien.org', 'gandi.link', 'garyvee.com', 'gaw.kr', 'gbod.org', 'gbpg.net', 'gbte.tech', 'gclnk.com', 'gdurl.com', 'gek.link', 'gen.cat', 'geni.us', 'genie.co.kr', 'getf.ly', 'geti.in', 'gfuel.ly', 'gh.io', 'ghkp.us', 'gi.lt', 'gigaz.in', 'git.io', 'github.co', 'gizmo.do', 'gjk.id', 'glbe.co', 'glblctzn.co', 'glblctzn.me', 'gldr.co', 'glmr.co', 'glo.bo', 'gma.abc', 'gmj.tw', 'go-link.ru', 'go.aws', 'go.btwrdn.co', 'go.cwtv.com', 'go.dbs.com', 'go.edh.tw', 'go.gcash.com', 'go.hny.co', 'go.id.me', 'go.intel-academy.com', 'go.intigriti.com', 'go.jc.fm', 'go.lamotte.fr', 'go.lu-h.de', 'go.ly', 'go.nasa.gov', 'go.nowth.is', 'go.osu.edu', 'go.qb.by', 'go.rebel.pl', 'go.shell.com', 'go.shr.lc', 'go.sony.tw', 'go.tinder.com', 'go.usa.gov', 'go.ustwo.games', 'go.vic.gov.au', 'godrk.de', 'gofund.me', 'gomomento.co', 'goo-gl.me', 'goo.by', 'goo.gl', 'goo.gle', 'goo.su', 'goolink.cc', 'goolnk.com', 'gosm.link', 'got.cr', 'got.to', 'gov.tw', 'gowat.ch', 'gph.to', 'gq.mn', 'gr.pn', 'grb.to', 'grdt.ai', 'grm.my', 'grnh.se', 'gtly.ink', 'gtly.to', 'gtne.ws', 'gtnr.it', 'gym.sh', 'haa.su', 'han.gl', 'hashi.co', 'hbaz.co', 'hbom.ax', 'her.is', 'herff.ly', 'hf.co', 'hi.kktv.to', 'hi.sat.cool', 'hi.switchy.io', 'hicider.com', 'hideout.cc', 'hill.cm', 'histori.ca', 'hmt.ai', 'hnsl.mn', 'homes.jp', 'hp.care', 'hpe.to', 'hrbl.me', 'href.li', 'ht.ly', 'htgb.co', 'htl.li', 'htn.to', 'httpslink.com', 'hubs.la', 'hubs.li', 'hubs.ly', 'huffp.st', 'hulu.tv', 'huma.na', 'hyperurl.co', 'hyperx.gg', 'i-d.co', 'i.coscup.org', 'i.mtr.cool', 'ibb.co', 'ibf.tw', 'ibit.ly', 'ibm.biz', 'ibm.co', 'ic9.in', 'icit.fr', 'icks.ro', 'iea.li', 'ifix.gd', 'ift.tt', 'iherb.co', 'ihr.fm', 'ii1.su', 'iii.im', 'iiil.io', 'il.rog.gg', 'ilang.in', 'illin.is', 'iln.io', 'ilnk.io', 'imdb.to', 'ind.pn', 'indeedhi.re', 'indy.st', 'infy.com', 'inlnk.ru', 'insd.io', 'insig.ht', 'instagr.am', 'intel.ly', 'interc.pt', 'intuit.me', 'invent.ge', 'inx.lv', 'ionos.ly', 'ipgrabber.ru', 'ipgraber.ru', 'iplogger.co', 'iplogger.com', 'iplogger.info', 'iplogger.org', 'iplogger.ru', 'iplwin.us', 'iqiyi.cn', 'irng.ca', 'is.gd', 'isw.pub', 'itsh.bo', 'itvty.com', 'ity.im', 'ix.sk', 'j.gs', 'j.mp', 'ja.cat', 'ja.ma', 'jb.gg', 'jcp.is', 'jkf.lv', 'jnfusa.org', 'joo.gl', 'jp.rog.gg', 'jpeg.ly', 'jsparty.fm', 'k-p.li', 'kas.pr', 'kask.us', 'katzr.net', 'kbank.co', 'kck.st', 'kf.org', 'kfrc.co', 'kg.games', 'kgs.link', 'kham.tw', 'kings.tn', 'kkc.tech', 'kkday.me', 'kkne.ws', 'kko.to', 'kkstre.am', 'kl.ik.my', 'klck.me', 'kli.cx', 'klmf.ly', 'ko.gl', 'kortlink.dk', 'kotl.in', 'kp.org', 'kpmg.ch', 'krazy.la', 'kuku.lu', 'kurl.ru', 'kutt.it', 'ky77.link', 'l.linklyhq.com', 'l.prageru.com', 'l8r.it', 'laco.st', 'lam.bo', 'lat.ms', 'latingram.my', 'lativ.tw', 'lbtw.tw', 'lc.chat', 'lc.cx', 'learn.to', 'lego.build', 'lemde.fr', 'letsharu.cc', 'lft.to', 'lih.kg', 'lihi.biz', 'lihi.cc', 'lihi.one', 'lihi.pro', 'lihi.tv', 'lihi.vip', 'lihi1.cc', 'lihi1.com', 'lihi1.me', 'lihi2.cc', 'lihi2.com', 'lihi2.me', 'lihi3.cc', 'lihi3.com', 'lihi3.me', 'lihipro.com', 'lihivip.com', 'liip.to', 'lin.ee', 'lin0.de', 'link.ac', 'link.infini.fr', 'link.tubi.tv', 'linkbun.com', 'linkd.in', 'linkjust.com', 'linko.page', 'linkopener.co', 'links2.me', 'linkshare.pro', 'linkye.net', 'livemu.sc', 'livestre.am', 'llk.dk', 'llo.to', 'lmg.gg', 'lmt.co', 'lmy.de', 'lnk.bz', 'lnk.direct', 'lnk.do', 'lnk.sk', 'lnkd.in', 'lnkiy.com', 'lnkiy.in', 'lnky.jp', 'lnnk.in', 'lnv.gy', 'lohud.us', 'lonerwolf.co', 'loom.ly', 'low.es', 'lprk.co', 'lru.jp', 'lsdl.es', 'lstu.fr', 'lt27.de', 'lttr.ai', 'ludia.gg', 'luminary.link', 'lurl.cc', 'lyksoomu.com', 'lzd.co', 'm.me', 'm.tb.cn', 'm101.org', 'm1p.fr', 'maac.io', 'maga.lu', 'man.ac.uk', 'many.at', 'maper.info', 'mapfan.to', 'mayocl.in', 'mbapp.io', 'mbayaq.co', 'mcafee.ly', 'mcd.to', 'mcgam.es', 'mck.co', 'mcys.co', 'me.sv', 'me2.kr', 'meck.co', 'meetu.ps', 'merky.de', 'metamark.net', 'mgnet.me', 'mgstn.ly', 'michmed.org', 'migre.me', 'minify.link', 'minilink.io', 'mitsha.re', 'mklnd.com', 'mm.rog.gg', 'mmz.li', 'mney.co', 'mng.bz', 'mnge.it', 'mnot.es', 'mo.ma', 'momo.dm', 'monster.cat', 'moo.im', 'moovit.me', 'mork.ro', 'mou.sr', 'mpl.pm', 'mrte.ch', 'mrx.cl', 'ms.spr.ly', 'msft.it', 'msi.gm', 'mstr.cl', 'mttr.io', 'mub.me', 'munbyn.biz', 'mvmtwatch.co', 'my.mtr.cool', 'mybmw.tw', 'myglamm.in', 'mylt.tv', 'mypoya.com', 'myppt.cc', 'mysp.ac', 'myumi.ch', 'myurls.ca', 'mz.cm', 'mzl.la', 'n.opn.tl', 'n.pr', 'n9.cl', 'name.ly', 'nature.ly', 'nav.cx', 'naver.me', 'nbc4dc.com', 'nbcbay.com', 'nbcchi.com', 'nbcct.co', 'nbcnews.to', 'nbzp.cz', 'nchcnh.info', 'nej.md', 'neti.cc', 'netm.ag', 'nflx.it', 'ngrid.com', 'njersy.co', 'nkbp.jp', 'nkf.re', 'nmrk.re', 'nnn.is', 'nnna.ru', 'nokia.ly', 'notlong.com', 'nr.tn', 'nswroads.work', 'ntap.com', 'ntck.co', 'ntn.so', 'ntuc.co', 'nus.edu', 'nvda.ws', 'nwppr.co', 'nwsdy.li', 'nxb.tw', 'nxdr.co', 'nycu.to', 'nydn.us', 'nyer.cm', 'nyp.st', 'nyr.kr', 'nyti.ms', 'o.vg', 'oal.lu', 'obank.tw', 'ock.cn', 'ocul.us', 'oe.cd', 'ofcour.se', 'offerup.co', 'offf.to', 'offs.ec', 'okt.to', 'omni.ag', 'on.bcg.com', 'on.bp.com', 'on.fb.me', 'on.ft.com', 'on.louisvuitton.com', 'on.mktw.net', 'on.natgeo.com', 'on.nba.com', 'on.ny.gov', 'on.nyc.gov', 'on.nypl.org', 'on.tcs.com', 'on.wsj.com', 'on9news.tv', 'onelink.to', 'onepl.us', 'onforb.es', 'onion.com', 'onx.la', 'oow.pw', 'opr.as', 'opr.news', 'optimize.ly', 'oran.ge', 'orlo.uk', 'osdb.link', 'oshko.sh', 'ouo.io', 'ouo.press', 'ourl.co', 'ourl.in', 'ourl.tw', 'outschooler.me', 'ovh.to', 'ow.ly', 'owl.li', 'owy.mn', 'oxelt.gl', 'oxf.am', 'oyn.at', 'p.asia', 'p.dw.com', 'p1r.es', 'p4k.in', 'pa.ag', 'packt.link', 'pag.la', 'pchome.link', 'pck.tv', 'pdora.co', 'pdxint.at', 'pe.ga', 'pens.pe', 'peoplem.ag', 'pepsi.co', 'pesc.pw', 'petrobr.as', 'pew.org', 'pewrsr.ch', 'pg3d.app', 'pgat.us', 'pgrs.in', 'philips.to', 'piee.pw', 'pin.it', 'pipr.es', 'pj.pizza', 'pl.kotl.in', 'pldthome.info', 'plu.sh', 'pnsne.ws', 'pod.fo', 'poie.ma', 'pojonews.co', 'politi.co', 'popm.ch', 'posh.mk', 'pplx.ai', 'ppt.cc', 'ppurl.io', 'pr.tn', 'prbly.us', 'prdct.school', 'preml.ge', 'prf.hn', 'prgress.co', 'prn.to', 'propub.li', 'pros.is', 'psce.pw', 'pse.is', 'psee.io', 'pt.rog.gg', 'ptix.co', 'puext.in', 'purdue.university', 'purefla.sh', 'puri.na', 'pwc.to', 'pxgo.net', 'pxu.co', 'pzdls.co', 'q.gs', 'qnap.to', 'qptr.ru', 'qr.ae', 'qr.net', 'qrco.de', 'qrs.ly', 'qvc.co', 'r-7.co', 'r.zecz.ec', 'rb.gy', 'rbl.ms', 'rblx.co', 'rch.lt', 'rd.gt', 'rdbl.co', 'rdcrss.org', 'rdcu.be', 'read.bi', 'readhacker.news', 'rebelne.ws', 'rebrand.ly', 'reconis.co', 'red.ht', 'redaz.in', 'redd.it', 'redir.ec', 'redir.is', 'redsto.ne', 'ref.trade.re', 'referer.us', 'refini.tv', 'regmovi.es', 'reline.cc', 'relink.asia', 'rem.ax', 'renew.ge', 'replug.link', 'rethinktw.cc', 'reurl.cc', 'reut.rs', 'rev.cm', 'revr.ec', 'rfr.bz', 'ringcentr.al', 'riot.com', 'rip.city', 'risu.io', 'ritea.id', 'rizy.ir', 'rlu.ru', 'rly.pt', 'rnm.me', 'ro.blox.com', 'rog.gg', 'roge.rs', 'rol.st', 'rotf.lol', 'rozhl.as', 'rpf.io', 'rptl.io', 'rsc.li', 'rsh.md', 'rtvote.com', 'ru.rog.gg', 'rushgiving.com', 'rushtix.co', 'rvtv.io', 'rvwd.co', 'rwl.io', 'ryml.me', 'rzr.to', 's.accupass.com', 's.coop', 's.g123.jp', 's.id', 's.mj.run', 's.ul.com', 's.uniqlo.com', 's.wikicharlie.cl', 's04.de', 's3vip.tw', 'saf.li', 'safelinking.net', 'safl.it', 'sail.to', 'samcart.me', 'sbird.co', 'sbux.co', 'sbux.jp', 'sc.mp', 'sc.org', 'sched.co', 'sck.io', 'scr.bi', 'scrb.ly', 'scuf.co', 'sdpbne.ws', 'sdu.sk', 'sdut.us', 'se.rog.gg', 'seagate.media', 'sealed.in', 'seedsta.rs', 'seiu.co', 'sejr.nl', 'selnd.com', 'seq.vc', 'sf3c.tw', 'sfca.re', 'sfcne.ws', 'sforce.co', 'sfty.io', 'sgq.io', 'shar.as', 'shiny.link', 'shln.me', 'sho.pe', 'shope.ee', 'shorl.com', 'short.gy', 'shorten.asia', 'shorturl.ae', 'shorturl.asia', 'shorturl.at', 'shorturl.com', 'shorturl.gg', 'shp.ee', 'shrtm.nu', 'sht.moe', 'shutr.bz', 'sie.ag', 'simp.ly', 'sina.lt', 'sincere.ly', 'sinourl.tw', 'sinyi.biz', 'sinyi.in', 'siriusxm.us', 'siteco.re', 'skimmth.is', 'skl.sh', 'skrat.it', 'skyurl.cc', 'slidesha.re', 'small.cat', 'smart.link', 'smarturl.it', 'smashed.by', 'smlk.es', 'smonty.co', 'smsb.co', 'smsng.news', 'smsng.us', 'smtvj.com', 'smu.gs', 'snd.sc', 'sndn.link', 'snip.link', 'snip.ly', 'snyk.co', 'so.arte', 'soc.cr', 'soch.us', 'social.ora.cl', 'socx.in', 'sokrati.ru', 'solsn.se', 'sou.nu', 'sourl.cn', 'sovrn.co', 'spcne.ws', 'spgrp.sg', 'spigen.co', 'split.to', 'splk.it', 'spoti.fi', 'spotify.link', 'spr.ly', 'spr.tn', 'sprtsnt.ca', 'sqex.to', 'sqrx.io', 'squ.re', 'srnk.us', 'ssur.cc', 'st.news', 'st8.fm', 'stan.md', 'stanford.io', 'starz.tv', 'stmodel.com', 'storycor.ps', 'stspg.io', 'stts.in', 'stuf.in', 'sumal.ly', 'suo.fyi', 'suo.im', 'supr.cl', 'supr.link', 'surl.li', 'svy.mk', 'swa.is', 'swag.run', 'swiy.co', 'swoo.sh', 'swtt.cc', 'sy.to', 'syb.la', 'synd.co', 'syw.co', 't-bi.link', 't-mo.co', 't.cn', 't.co', 't.iotex.me', 't.libren.ms', 't.ly', 't.me', 't.tl', 't1p.de', 't2m.io', 'ta.co', 'tabsoft.co', 'taiwangov.com', 'tanks.ly', 'tbb.tw', 'tbrd.co', 'tcat.tc', 'tcrn.ch', 'tdrive.li', 'tdy.sg', 'tek.io', 'temu.to', 'ter.li', 'tg.pe', 'tgam.ca', 'tgr.ph', 'thatis.me', 'thd.co', 'thedo.do', 'thefp.pub', 'thein.fo', 'thesne.ws', 'thetim.es', 'thght.works', 'thinfi.com', 'thls.co', 'thn.news', 'thr.cm', 'thrill.to', 'ti.me', 'tibco.cm', 'tibco.co', 'tidd.ly', 'tim.com.vc', 'tinu.be', 'tiny.cc', 'tiny.ee', 'tiny.one', 'tiny.pl', 'tinyarro.ws', 'tinylink.net', 'tinyurl.com', 'tinyurl.hu', 'tinyurl.mobi', 'tktwb.tw', 'tl.gd', 'tlil.nl', 'tlrk.it', 'tmblr.co', 'tmsnrt.rs', 'tmz.me', 'tnne.ws', 'tnsne.ws', 'tnvge.co', 'tnw.to', 'tny.cz', 'tny.im', 'tny.so', 'to.ly', 'to.pbs.org', 'toi.in', 'tokopedia.link', 'tonyr.co', 'topt.al', 'toyota.us', 'tpc.io', 'tpmr.com', 'tprk.us', 'tr.ee', 'trackurl.link', 'trade.re', 'travl.rs', 'trib.al', 'trib.in', 'troy.hn', 'trt.sh', 'trymongodb.com', 'tsbk.tw', 'tsta.rs', 'tt.vg', 'tvote.org', 'tw.rog.gg', 'tw.sv', 'twb.nz', 'twm5g.co', 'twou.co', 'twtr.to', 'txdl.top', 'txul.cn', 'u.nu', 'u.shxj.pw', 'u.to', 'u1.mnge.co', 'ua.rog.gg', 'uafly.co', 'ubm.io', 'ubnt.link', 'ubr.to', 'ucbexed.org', 'ucla.in', 'ufcqc.link', 'ugp.io', 'ui8.ru', 'uk.rog.gg', 'ukf.me', 'ukoeln.de', 'ul.rs', 'ul.to', 'ul3.ir', 'ulvis.net', 'ume.la', 'umlib.us', 'unc.live', 'undrarmr.co', 'uni.cf', 'unipapa.co', 'uofr.us', 'uoft.me', 'up.to', 'upmchp.us', 'ur3.us', 'urb.tf', 'urbn.is', 'url.cn', 'url.cy', 'url.ie', 'url2.fr', 'urla.ru', 'urlgeni.us', 'urli.ai', 'urlify.cn', 'urlr.me', 'urls.fr', 'urls.kr', 'urluno.com', 'urly.co', 'urly.fi', 'urlz.fr', 'urlzs.com', 'urt.io', 'us.rog.gg', 'usanet.tv', 'usat.ly', 'usm.ag', 'utm.to', 'utn.pl', 'utraker.com', 'v.gd', 'v.redd.it', 'vai.la', 'vbly.us', 'vd55.com', 'vercel.link', 'vi.sa', 'vi.tc', 'viaalto.me', 'viaja.am', 'vineland.dj', 'viraln.co', 'vivo.tl', 'vk.cc', 'vk.sv', 'vn.rog.gg', 'vntyfr.com', 'vo.la', 'vodafone.uk', 'vogue.cm', 'voicetu.be', 'volvocars.us', 'vonq.io', 'vrnda.us', 'vtns.io', 'vur.me', 'vurl.com', 'vvnt.co', 'vxn.link', 'vypij.bar', 'vz.to', 'vzturl.com', 'w.idg.de', 'w.wiki', 'w5n.co', 'wa.link', 'wa.me', 'wa.sv', 'waa.ai', 'waad.co', 'wahoowa.net', 'walk.sc', 'walkjc.org', 'wapo.st', 'warby.me', 'warp.plus', 'wartsi.ly', 'way.to', 'wb.md', 'wbby.co', 'wbur.fm', 'wbze.de', 'wcha.it', 'we.co', 'weall.vote', 'weare.rs', 'wee.so', 'wef.ch', 'wellc.me', 'wenk.io', 'wf0.xin', 'whatel.se', 'whcs.law', 'whi.ch', 'whoel.se', 'whr.tn', 'wi.se', 'win.gs', 'wit.to', 'wjcf.co', 'wkf.ms', 'wmojo.com', 'wn.nr', 'wndrfl.co', 'wo.ws', 'wooo.tw', 'wp.me', 'wpbeg.in', 'wrctr.co', 'wrd.cm', 'wrem.it', 'wun.io', 'ww7.fr', 'wwf.to', 'wwp.news', 'www.shrunken.com', 'x.gd', 'xbx.lv', 'xerox.bz', 'xfin.tv', 'xfl.ag', 'xfru.it', 'xgam.es', 'xor.tw', 'xpr.li', 'xprt.re', 'xqss.org', 'xrds.ca', 'xrl.us', 'xurl.es', 'xvirt.it', 'xyvid.tv', 'y.ahoo.it', 'y2u.be', 'yadi.sk', 'yal.su', 'yelp.to', 'yex.tt', 'yhoo.it', 'yip.su', 'yji.tw', 'ynews.page.link', 'yoox.ly', 'your.ls', 'yourls.org', 'yourwish.es', 'youtu.be', 'yubi.co', 'yun.ir', 'z23.ru', 'zat.ink', 'zaya.io', 'zc.vg', 'zcu.io', 'zd.net', 'zdrive.li', 'zdsk.co', 'zecz.ec', 'zeep.ly', 'zez.kr', 'zi.ma', 'ziadi.co', 'zipurl.fr', 'zln.do', 'zlr.my', 'zlra.co', 'zlw.re', 'zoho.to', 'zopen.to', 'zovpart.com', 'zpr.io', 'zuki.ie', 'zuplo.link', 'zurb.us', 'zurins.uk', 'zurl.co', 'zurl.ir', 'zurl.ws', 'zws.im', 'zxc.li', 'zynga.my', 'zywv.us', 'zzb.bz', 'zzu.info'
}

# --- Feature Extraction Functions ---

def get_url_components(url):
    """Parse URL into components."""
    try:
        # Ensure URL has a scheme, default to http if missing
        if not isinstance(url, str):
             url = str(url) # Attempt to cast to string if not already
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        parsed = urlparse(url)
        # Use tldextract to accurately get subdomain, domain, suffix
        extracted = tldextract.extract(url)
        domain = extracted.domain
        subdomain = extracted.subdomain
        suffix = extracted.suffix # TLD
        registered_domain = extracted.top_domain_under_public_suffix #extracted.registered_domain # domain + suffix
        path = parsed.path
        query = parsed.query
        fragment = parsed.fragment
        netloc = parsed.netloc # Includes port if present
        hostname = parsed.hostname # Excludes port
        return {
            "url": url,
            "scheme": parsed.scheme,
            "netloc": netloc,
            "hostname": hostname,
            "domain": domain,
            "subdomain": subdomain,
            "suffix": suffix, # TLD
            "registered_domain": registered_domain,
            "path": path,
            "query": query,
            "fragment": fragment
        }
    except Exception as e:
        logger.warning(f"Error parsing URL 	{url}	: {e}")
        # Return default empty values on error
        return {
            "url": url,
            "scheme": None, "netloc": None, "hostname": None,
            "domain": None, "subdomain": None, "suffix": None,
            "registered_domain": None, "path": None, "query": None,
            "fragment": None
        }

def calculate_entropy(text):
    """Calculate Shannon entropy of a string."""
    if not text or not isinstance(text, str):
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob if p > 0]) # Added check p > 0
    return entropy

def extract_lexical_features(url_components):
    """Extract all lexical features from parsed URL components."""
    features = {}
    url = url_components.get("url", "")
    hostname = url_components.get("hostname", "") or ""
    domain = url_components.get("domain", "") or ""
    subdomain = url_components.get("subdomain", "") or ""
    suffix = url_components.get("suffix", "") or ""
    registered_domain = url_components.get("registered_domain", "") or ""
    path = url_components.get("path", "") or ""
    query = url_components.get("query", "") or ""
    
    # Ensure all components are strings for safety
    url = str(url)
    hostname = str(hostname)
    domain = str(domain)
    subdomain = str(subdomain)
    suffix = str(suffix)
    registered_domain = str(registered_domain)
    path = str(path)
    query = str(query)

    # --- Length Features ---
    features["url_length"] = len(url)
    features["hostname_length"] = len(hostname)
    features["path_length"] = len(path)
    features["query_length"] = len(query)
    features["domain_length"] = len(domain)
    features["subdomain_length"] = len(subdomain)
    features["tld_length"] = len(suffix)
    
    # --- Count Features ---
    features["count_dot"] = url.count(".")
    features["count_hyphen"] = url.count("-")
    features["count_underline"] = url.count("_")
    features["count_slash"] = url.count("/")
    features["count_question"] = url.count("?")
    features["count_equal"] = url.count("=")
    features["count_at"] = url.count("@")
    features["count_and"] = url.count("&")
    features["count_exclamation"] = url.count("!")
    features["count_space"] = url.count(" ")
    features["count_tilde"] = url.count("~")
    features["count_comma"] = url.count(",")
    features["count_plus"] = url.count("+")
    features["count_asterisk"] = url.count("*")
    features["count_hashtag"] = url.count("#")
    features["count_dollar"] = url.count("$")
    features["count_percent"] = url.count("%")
    features["count_digits"] = sum(c.isdigit() for c in url)
    features["count_letters"] = sum(c.isalpha() for c in url)
    features["count_special_chars"] = len(url) - features["count_digits"] - features["count_letters"]
    features["count_encoded_chars"] = len(re.findall(r"%[0-9a-fA-F]{2}", url))
    features["count_subdomains"] = subdomain.count(".") + 1 if subdomain else 0
    features["count_path_levels"] = path.count("/") - 1 if path.startswith("/") else path.count("/")
    features["count_query_params"] = len(query.split("&")) if query else 0

    # --- Binary/Presence Features ---
    features["has_ip_address"] = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname) else 0
    features["has_https"] = 1 if url_components.get("scheme") == "https" else 0
    features["has_suspicious_tld"] = 1 if suffix and ("." + suffix) in SUSPICIOUS_TLDS else 0 # Add dot for comparison
    features["is_shortened"] = 1 if registered_domain in SHORTENING_SERVICES else 0
    features["has_at_symbol"] = 1 if "@" in url else 0
    features["has_double_slash_in_path"] = 1 if "//" in path else 0
    features["has_sensitive_words"] = 1 if re.search(r"login|signin|password|account|update|secure|verify|banking|ebay|paypal|admin|cmd|shell|script", url, re.IGNORECASE) else 0
    features["has_hex_encoding"] = 1 if features["count_encoded_chars"] > 0 else 0
    features["has_port_in_url"] = 1 if url_components.get("netloc") and ":" in url_components["netloc"] and not url_components["netloc"].endswith((":80", ":443")) else 0
    features["has_query"] = 1 if query else 0
    features["has_fragment"] = 1 if url_components.get("fragment") else 0

    # --- Ratio Features ---
    url_len = features["url_length"] if features["url_length"] > 0 else 1 # Avoid division by zero
    features["ratio_digits_url"] = features["count_digits"] / url_len
    features["ratio_letters_url"] = features["count_letters"] / url_len
    features["ratio_special_chars_url"] = features["count_special_chars"] / url_len
    hostname_len = features["hostname_length"] if features["hostname_length"] > 0 else 1
    features["ratio_digits_hostname"] = sum(c.isdigit() for c in hostname) / hostname_len
    path_len = features["path_length"] if features["path_length"] > 0 else 1
    features["ratio_digits_path"] = sum(c.isdigit() for c in path) / path_len
    query_len = features["query_length"] if features["query_length"] > 0 else 1
    features["ratio_digits_query"] = sum(c.isdigit() for c in query) / query_len

    # --- Entropy Features ---
    features["entropy_url"] = calculate_entropy(url)
    features["entropy_hostname"] = calculate_entropy(hostname)
    features["entropy_path"] = calculate_entropy(path)
    features["entropy_query"] = calculate_entropy(query)
    features["entropy_domain"] = calculate_entropy(domain)

    # --- Domain/Path Token Features ---
    path_tokens = [t for t in re.split(r"[/\-_.]", path) if t] # Filter empty tokens
    domain_tokens = [t for t in re.split(r"[\-_.]", domain) if t]
    hostname_tokens = [t for t in re.split(r"[\-_.]", hostname) if t]
    
    features["num_path_tokens"] = len(path_tokens)
    features["avg_path_token_length"] = sum(len(t) for t in path_tokens) / len(path_tokens) if path_tokens else 0
    features["max_path_token_length"] = max(len(t) for t in path_tokens) if path_tokens else 0
    
    features["num_domain_tokens"] = len(domain_tokens)
    features["avg_domain_token_length"] = sum(len(t) for t in domain_tokens) / len(domain_tokens) if domain_tokens else 0
    features["max_domain_token_length"] = max(len(t) for t in domain_tokens) if domain_tokens else 0

    features["num_hostname_tokens"] = len(hostname_tokens)
    features["avg_hostname_token_length"] = sum(len(t) for t in hostname_tokens) / len(hostname_tokens) if hostname_tokens else 0
    features["max_hostname_token_length"] = max(len(t) for t in hostname_tokens) if hostname_tokens else 0

    # --- Specific Character Position Features ---
    try:
        features["first_digit_index"] = next((i for i, char in enumerate(url) if char.isdigit()), -1)
    except StopIteration:
        features["first_digit_index"] = -1
    try:
        features["first_letter_index"] = next((i for i, char in enumerate(url) if char.isalpha()), -1)
    except StopIteration:
        features["first_letter_index"] = -1
    features["first_slash_index"] = url.find("/")
    features["last_slash_index"] = url.rfind("/")
    features["first_dot_index"] = url.find(".")
    features["last_dot_index"] = url.rfind(".")

    return features

# --- Main Processing Logic ---
def process_urls(input_filepath, output_dir):
    """Reads URLs from input CSV, extracts features, and saves to a new CSV."""
    logger.info(f"Starting lexical feature extraction for: {input_filepath}")
    
    try:
        # Read all columns from the input file
        df = pd.read_csv(input_filepath)
        logger.info(f"Read {len(df)} rows from {input_filepath}")
        
        # Check if 'url' column exists
        if 'url' not in df.columns:
            logger.error("Input file must contain a 'url' column")
            return
            
    except FileNotFoundError:
        logger.error(f"Input file not found: {input_filepath}")
        return
    except Exception as e:
        logger.error(f"Unexpected error reading {input_filepath}: {e}")
        return

    # Drop rows with missing URLs and ensure type is string
    original_columns = df.columns.tolist()
    df.dropna(subset=["url"], inplace=True)
    df["url"] = df["url"].astype(str)
    
    if df.empty:
        logger.warning("No valid URLs found in the input file after cleaning.")
        return

    logger.info(f"Processing {len(df)} URLs...")

    # 1. Parse URLs
    url_components_list = df["url"].apply(get_url_components).tolist()
    
    # 2. Extract Lexical Features
    lexical_features_list = [extract_lexical_features(comp) for comp in url_components_list]
    
    # 3. Create DataFrame from features
    features_df = pd.DataFrame(lexical_features_list)
    
    # 4. Combine original data with features
    # Use index alignment for robust joining
    final_df = pd.concat([df.reset_index(drop=True), features_df.reset_index(drop=True)], axis=1)

    # Reorder columns to have original columns first, followed by new features
    # Get the list of new feature columns (all columns not in the original)
    new_columns = [col for col in final_df.columns if col not in original_columns]
    final_df = final_df[original_columns + new_columns]

    # --- Generate Output Filename ---
    input_basename = os.path.basename(input_filepath)
    # Replace "http_status" with "lexical_features"
    output_basename = input_basename.replace("http_status", "lexical_features", 1) # Replace only the first occurrence
    if output_basename == input_basename:
        # If replacement didn't happen (e.g., "http_status" not found), prepend instead
        logger.warning(f"	http_status	 not found in input filename 	{input_basename}	. Prepending 	lexical_features_	.")
        output_basename = f"lexical_features_{input_basename}"
        
    output_filepath = os.path.join(output_dir, output_basename)
    logger.info(f"Generated output filename: {output_basename}")

    # --- Save Output ---
    try:
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        final_df.to_csv(output_filepath, index=False)
        logger.info(f"Successfully saved {len(final_df)} rows with lexical features to: {output_filepath}")
    except Exception as e:
        logger.error(f"Error saving output file {output_filepath}: {e}")

# --- Script Entry Point ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract lexical features from URLs in a CSV file.")
    parser.add_argument("--input-file", required=True, help="Path to the input CSV file containing URLs (must have a 	url	 column). Expected filename format like 	...http_status...	")
    parser.add_argument("--output-dir", default="lexical_features", help="Directory to save the output CSV file (default: lexical_features)")
    
    args = parser.parse_args()
    
    process_urls(args.input_file, args.output_dir)